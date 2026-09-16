rule Win_Trojan_TimerJack_1
{
strings:
	$a0 = { ba52049c2eff1edc01e83500b440b9520433d2e81dfeb801575a59e815feb43ee810fe5a1f }


condition:
	$a0
}