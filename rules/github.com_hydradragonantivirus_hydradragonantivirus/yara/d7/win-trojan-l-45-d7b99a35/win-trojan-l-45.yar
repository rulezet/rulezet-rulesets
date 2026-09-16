rule Win_Trojan_L_45
{
strings:
	$a0 = { b910018137053081770209e183c304e2f2 }


condition:
	$a0
}