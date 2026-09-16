rule Win_Trojan_Monster_58
{
strings:
	$a0 = { b94602be????fc300446e2fbeb25 }


condition:
	$a0
}