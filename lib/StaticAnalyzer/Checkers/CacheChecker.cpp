#include "clang/AST/Stmt.h"
#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/AnalysisManager.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/AnalysisManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"

#include <queue>
#include <set>
#include <unordered_map>
#include <utility>

using namespace clang;
using namespace ento;
using namespace llvm;

struct CacheState {
private:
    enum Kind { VALID, INVALID } k;
    CacheState(Kind inK) : k(inK) { }

public:
    bool operator==(const CacheState &x) const {
        return k == x.k;
    }

    void Profile(llvm::FoldingSetNodeID &id) const {
        id.AddInteger(k);
    }

    bool isValid() const { return k == VALID; }
    bool isInvalid() const { return k == INVALID; }

    static CacheState getValid() { return CacheState(VALID); }
    static CacheState getInvalid() { return CacheState(INVALID); }
};

struct CacheSymbols {
    std::set<SymbolRef>* symbolSet;

public:
    bool operator==(const CacheSymbols &x) const {
        return symbolSet == x.symbolSet;
    }

    void Profile(llvm::FoldingSetNodeID &id) const {
        id.AddPointer(symbolSet);
    }
};

struct SymbolCaches {
    std::set<SymbolRef>* cacheSet;

public:
    bool operator==(const SymbolCaches &x) const {
        return cacheSet == x.cacheSet;
    }

    void Profile(llvm::FoldingSetNodeID &id) const {
        id.AddPointer(cacheSet);
    }
};

struct TaintedSymbols {
    std::set<SymbolRef>* taintedSet;

public:
    bool operator==(const TaintedSymbols &x) const {
        return taintedSet == x.taintedSet;
    }

    void Profile(llvm::FoldingSetNodeID &id) const {
        id.AddPointer(taintedSet);
    }
};

class CacheChecker : public Checker<check::PostCall,
                                    check::PreCall,
                                    check::Location> {
private:
    CallDescription hashmapNewFn, hashmapClearFn, hashmapPutFn, hashmapGetFn, hashmapRemoveFn;
    std::unique_ptr<BugType> cacheBugType;

    void checkClearFn(const CallEvent &call, CheckerContext &c) const;
    void checkGetFn(const CallEvent &call, CheckerContext &c) const;
    void checkRemoveFn(const CallEvent &call, CheckerContext &c) const;

    void checkNewFn(const CallEvent &call, CheckerContext &c) const;
    void checkPutFn(const CallEvent &call, CheckerContext &c) const;

public:
    CacheChecker();

    void checkPostCall(const CallEvent &call, CheckerContext &c) const;
    void checkPreCall(const CallEvent &call, CheckerContext &c) const;
    void checkLocation(SVal sval, bool isLoad, const Stmt *s, CheckerContext &c) const;
    
    bool checkUseAfterFree(SymbolRef symbol, SourceRange range, CheckerContext& c) const;
    bool isSymbolValid(SymbolRef cacheSymbol, CheckerContext& c) const;
    void reportUseAfterFree(SymbolRef symbol, SourceRange range, CheckerContext &c) const;

    void printSymbolStateMap(CheckerContext &c) const;
};

// A map from the hashmap to its cached symbols
REGISTER_MAP_WITH_PROGRAMSTATE(CacheSymbolMap, SymbolRef, CacheSymbols)

// A map from the symbol to its caches
REGISTER_MAP_WITH_PROGRAMSTATE(SymbolCacheMap, SymbolRef, SymbolCaches)

// A map from the symbol to its cache state
REGISTER_MAP_WITH_PROGRAMSTATE(SymbolStateMap, SymbolRef, CacheState)

CacheChecker::CacheChecker()
        : hashmapNewFn("internal_hashmap_new"), // Use internal_hashmap_new() because hashmap_new() is just a macro
          hashmapClearFn("hashmap_clear", 1),
          hashmapPutFn("hashmap_put", 3),
          hashmapGetFn("hashmap_get", 2),
          hashmapRemoveFn("hashmap_remove", 2) {
    // Initialize the bug types.
    cacheBugType.reset(
        new BugType(this, /*Name=*/"Use-after-free", /*Category=*/"Cache Error"));
}

void CacheChecker::checkClearFn(const CallEvent &call, CheckerContext &c) const {
    SymbolRef cache = call.getArgSVal(0).getAsSymbol();
    if (!cache)
        return;

    ProgramStateRef state = c.getState();
    const CacheSymbols* cacheSymbols = state->get<CacheSymbolMap>(cache);
    if (!cacheSymbols)
        return;

    std::set<SymbolRef>* symbolSet = cacheSymbols->symbolSet;

    // Invalidate all the symbols in this cache
    for (const auto& cacheSymbol : *symbolSet) {
        state = state->remove<SymbolCacheMap>(cacheSymbol);
        state = state->set<SymbolStateMap>(cacheSymbol, CacheState::getInvalid());
    }

    state = state->remove<CacheSymbolMap>(cache);
    c.addTransition(state);
}

void CacheChecker::checkGetFn(const CallEvent &call, CheckerContext &c) const {
    SymbolRef cache = call.getArgSVal(0).getAsSymbol();
    if (!cache)
        return;

    SymbolRef key = call.getArgSVal(1).getAsSymbol();
    if (!key)
        return;

    ProgramStateRef state = c.getState();

    // If this symbol's state is invalid, then we report a use-after-free
    if (!checkUseAfterFree(key, call.getSourceRange(), c))
        return;

    SymbolRef returnVal = call.getReturnValue().getAsSymbol();
    if (!returnVal)
        return;

    // Track this return value in the CacheSymbolMap
    const CacheSymbols* cacheSymbols = state->get<CacheSymbolMap>(cache);
    if (cacheSymbols) {
        cacheSymbols->symbolSet->insert(returnVal);
        state = state->set<CacheSymbolMap>(cache, *cacheSymbols);
    }

    // Track this return value in the SymbolCacheMap
    const SymbolCaches* symbolCaches = state->get<SymbolCacheMap>(returnVal);
    if (symbolCaches) {
        symbolCaches->cacheSet->insert(cache);
        state = state->set<SymbolCacheMap>(returnVal, *symbolCaches);
    }

    // Update this return value to have a VALID state
    state = state->set<SymbolStateMap>(returnVal, CacheState::getValid());
    c.addTransition(state);
}

void CacheChecker::checkRemoveFn(const CallEvent &call, CheckerContext &c) const {
    SymbolRef cache = call.getArgSVal(0).getAsSymbol();
    if (!cache)
        return;

    SymbolRef key = call.getArgSVal(1).getAsSymbol();
    if (!key)
        return;

    // TODO(samanthayu): Handle tainted values
    ProgramStateRef state = c.getState();
    state = state->remove<CacheSymbolMap>(cache);
    state = state->remove<SymbolCacheMap>(key);
    state = state->set<SymbolStateMap>(key, CacheState::getInvalid());
    c.addTransition(state);
}

void CacheChecker::checkPreCall(const CallEvent &call, CheckerContext &c) const {
    if (call.isCalled(hashmapClearFn)) {
        checkClearFn(call, c);
    } else if (call.isCalled(hashmapGetFn)) {
        checkGetFn(call, c);
    } else if (call.isCalled(hashmapRemoveFn)) {
        checkRemoveFn(call, c);
    }
}

void CacheChecker::checkNewFn(const CallEvent &call, CheckerContext &c) const {
    SymbolRef cache = call.getReturnValue().getAsSymbol();
    if (!cache)
        return;

    ProgramStateRef state = c.getState();

    // Insert a new set for this cache into CacheSymbolMap
    CacheSymbols cacheSymbols;
    cacheSymbols.symbolSet = new std::set<SymbolRef>();
    state = state->set<CacheSymbolMap>(cache, cacheSymbols);

    c.addTransition(state);
}

void CacheChecker::checkPutFn(const CallEvent &call, CheckerContext &c) const {
    SymbolRef cache = call.getArgSVal(0).getAsSymbol();
    if (!cache)
        return;

    SymbolRef key = call.getArgSVal(2).getAsSymbol();
    if (!key)
        return;

    ProgramStateRef state = c.getState();

    // Update CacheSymbolMap with this key
    const CacheSymbols* cacheSymbols = state->get<CacheSymbolMap>(cache);
    if (cacheSymbols) {
        cacheSymbols->symbolSet->insert(key);
        state = state->set<CacheSymbolMap>(cache, *cacheSymbols);
    }

    // Update SymbolCacheMap with this key
    const SymbolCaches* symbolCaches = state->get<SymbolCacheMap>(key);
    if (symbolCaches) {
        symbolCaches->cacheSet->insert(cache);
        state = state->set<SymbolCacheMap>(key, *symbolCaches);
    }

    // Update this key to have a VALID state
    state = state->set<SymbolStateMap>(key, CacheState::getValid());
    c.addTransition(state);
}

void CacheChecker::checkPostCall(const CallEvent &call, CheckerContext &c) const {
    if (call.isCalled(hashmapNewFn)) {
        checkNewFn(call, c);
    } else if (call.isCalled(hashmapPutFn)) {
        checkPutFn(call, c);
    }
}

void CacheChecker::checkLocation(SVal sval, bool isLoad, const Stmt *s, CheckerContext &c) const {
    SymbolRef symbol = sval.getLocSymbolInBase();
    if (symbol) {
        checkUseAfterFree(symbol, s->getSourceRange(), c);
    }
}

bool CacheChecker::checkUseAfterFree(SymbolRef symbol, SourceRange range, CheckerContext& c) const {
    if (!isSymbolValid(symbol, c)) {
        reportUseAfterFree(symbol, range, c);
        return false;
    }
    return true;
}

bool CacheChecker::isSymbolValid(SymbolRef symbol, CheckerContext& c) const {
    ProgramStateRef state = c.getState();
    const CacheState* cacheState = state->get<SymbolStateMap>(symbol);

    // We return true if we have not tracked this symbol; e.g. Cache itself
    if (!cacheState)
        return true;

    if (*cacheState == CacheState::getInvalid()) {
        outs() << "ERROR: Found cache use-after-free\n";
        return false;
    }
    return true;
}

void CacheChecker::reportUseAfterFree(SymbolRef symbol, SourceRange range, CheckerContext &c) const {
    // We reached a bug, stop exploring the path here by generating a sink.
    ExplodedNode *ErrNode = c.generateErrorNode();

    // If we've already reached this node on another path, return.
    if (!ErrNode)
        return;
 
    // Generate the report.
    auto report = std::make_unique<PathSensitiveBugReport>(
       *cacheBugType, "Using cached memory that was previously freed", ErrNode);
    report->markInteresting(symbol);
    report->addRange(range);
    c.emitReport(std::move(report));
}

void CacheChecker::printSymbolStateMap(CheckerContext &c) const {
    ProgramStateRef state = c.getState();
    SymbolStateMapTy symbolStateMap = state->get<SymbolStateMap>();
    for (auto iter = symbolStateMap.begin(); iter != symbolStateMap.end(); iter++) {
        outs() << ">  Key: ";
        iter.getKey()->dumpToStream(outs());
        outs() << "; Value: " << iter.getData().isValid() << "\n";
    }
}

void ento::registerCacheChecker(CheckerManager &mgr) {
    mgr.registerChecker<CacheChecker>();
}

// This checker should be enabled regardless of how language options are set.
bool ento::shouldRegisterCacheChecker(const CheckerManager &mgr) {
  return true;
}