import cpp
import semmle.code.cpp.dataflow.TaintTracking
import DataFlow::PathGraph

class NetworkByteSwap extends Expr
{
    NetworkByteSwap()
    {
        exists(
            MacroInvocation m_invoke | 
            this = m_invoke.getExpr() and
            m_invoke.getMacro().getName().regexpMatch("ntoh.*")
        )
    }
}

class Config extends TaintTracking::Configuration {
  Config() { this = "NetworkToMemFuncLength" }

  override predicate isSource(DataFlow::Node source) 
  {
      exists(
          NetworkByteSwap nbs |
          nbs = source.asExpr()
      )
  }
  override predicate isSink(DataFlow::Node sink) 
  {
    exists(
        FunctionCall f_Call |
        sink.getLocation() = f_Call.getLocation() and
        f_Call.getTarget().getName() = "memcpy"
    )
  }
}

from Config cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink, source, sink, "Network byte swap flows to memcpy"

