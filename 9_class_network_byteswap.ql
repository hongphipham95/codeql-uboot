import cpp

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


from NetworkByteSwap n
select n, "Network byte swap" 