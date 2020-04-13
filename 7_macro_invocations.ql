import cpp

from MacroInvocation m_invoke
where m_invoke.getMacro().getName().regexpMatch("ntoh.*")
select m_invoke
