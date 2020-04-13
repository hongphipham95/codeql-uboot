import cpp

from FunctionCall f_call
where f_call.getTarget().getName() = "memcpy"
select f_call
