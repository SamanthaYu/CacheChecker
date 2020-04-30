#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
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
                                    check::PreCall> {
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
};

// A map from the hashmap to its cached symbols
REGISTER_MAP_WITH_PROGRAMSTATE(CacheSymbolMap, SymbolRef, CacheSymbols)

// A map from the symbol to its caches
REGISTER_MAP_WITH_PROGRAMSTATE(SymbolCacheMap, SymbolRef, SymbolCaches)

// A map from the symbol to its cache state
REGISTER_MAP_WITH_PROGRAMSTATE(SymbolStateMap, SymbolRef, CacheState)

CacheChecker::CacheChecker()
        : hashmapNewFn("hashmap_new"), hashmapClearFn("hashmap_clear", 1),
          hashmapPutFn("hashmap_put", 3), hashmapGetFn("hashmap_get", 2),
          hashmapRemoveFn("hashmap_remove", 2) {
    // Initialize the bug types.
    cacheBugType.reset(
        new BugType(this, /*Name=*/"Use-after-free", /*Category=*/"Cache Error"));
}

void CacheChecker::checkClearFn(const CallEvent &call, CheckerContext &c) const {
    outs() << "SY - checkClearFn()\n";
    SymbolRef cache = call.getArgSVal(0).getAsSymbol();
    if (!cache)
        return;

    outs() << ">  - Cache: ";
    cache->dumpToStream(outs());
    outs() << "\n";

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
    outs() << "SY - checkGetFn()\n";
    SymbolRef cache = call.getArgSVal(0).getAsSymbol();
    if (!cache)
        return;

    outs() << ">  - Cache: ";
    cache->dumpToStream(outs());
    outs() << "\n";

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
    outs() << "SY - checkRemoveFn()\n";
    SymbolRef cache = call.getArgSVal(0).getAsSymbol();
    if (!cache)
        return;

    outs() << ">  - Cache: ";
    cache->dumpToStream(outs());
    outs() << "\n";

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
    outs() << "SY - checkNewFn()\n";
    SymbolRef cache = call.getReturnValue().getAsSymbol();
    if (!cache)
        return;

    outs() << ">  - Cache: ";
    cache->dumpToStream(outs());
    outs() << "\n";

    ProgramStateRef state = c.getState();

    // Insert a new set for this cache into CacheSymbolMap
    CacheSymbols cacheSymbols;
    cacheSymbols.symbolSet = new std::set<SymbolRef>();
    state = state->set<CacheSymbolMap>(cache, cacheSymbols);

    c.addTransition(state);
}

void CacheChecker::checkPutFn(const CallEvent &call, CheckerContext &c) const {
    outs() << "SY - checkPutFn()\n";
    SymbolRef cache = call.getArgSVal(0).getAsSymbol();
    if (!cache)
        return;

    outs() << ">  - Cache: ";
    cache->dumpToStream(outs());
    outs() << "\n";

    SymbolRef key = call.getArgSVal(2).getAsSymbol();
    if (!key)
        return;

    outs() << ">  - Key: ";
    key->dumpToStream(outs());
    outs() << "\n";

    ProgramStateRef state = c.getState();

    // Update CacheSymbolMap with this key
    const CacheSymbols* cacheSymbols = state->get<CacheSymbolMap>(cache);
    if (cacheSymbols) {
        outs() << "SY - Cache symbols\n";
        cacheSymbols->symbolSet->insert(key);
        state = state->set<CacheSymbolMap>(cache, *cacheSymbols);
    }

    // Update SymbolCacheMap with this key
    const SymbolCaches* symbolCaches = state->get<SymbolCacheMap>(key);
    if (symbolCaches) {
        outs() << "SY - Symbol caches\n";
        symbolCaches->cacheSet->insert(cache);
        outs() << "SY - Insert\n";
        state = state->set<SymbolCacheMap>(key, *symbolCaches);
        outs() << "SY - Set cache\n";
    }

    // Update this key to have a VALID state
    outs() << "SY - Valid state\n";
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
    outs() << "SY - checkLocation()\n";
    SymbolRef symbol = sval.getLocSymbolInBase();
    if (symbol) {
        checkUseAfterFree(symbol, s->getSourceRange(), c);
    }
}

bool CacheChecker::checkUseAfterFree(SymbolRef symbol, SourceRange range, CheckerContext& c) const {
    outs() << "SY - checkUseAfterFree()\n";
    if (isSymbolValid(symbol, c)) {
        reportUseAfterFree(symbol, range, c);
        return true;
    }
    return false;
}

bool CacheChecker::isSymbolValid(SymbolRef cacheSymbol, CheckerContext& c) const {
    outs() << "SY - isSymbolValid()\n";
    ProgramStateRef state = c.getState();
    const CacheState* cacheState = state->get<SymbolStateMap>(cacheSymbol);
    
    if (!cacheState || *cacheState == CacheState::getInvalid()) {
        return false;
    }
    return true;
}

void CacheChecker::reportUseAfterFree(SymbolRef symbol, SourceRange range, CheckerContext &c) const {
    outs() << "SY - reportUseAfterFree()\n";
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

void ento::registerCacheChecker(CheckerManager &mgr) {
    mgr.registerChecker<CacheChecker>();
}

// This checker should be enabled regardless of how language options are set.
bool ento::shouldRegisterCacheChecker(const CheckerManager &mgr) {
  return true;
}