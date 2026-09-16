rule Win_Trojan_Monster_57
{
strings:
	$a0 = { b93602be????fc300446e2fbeb24 }


condition:
	$a0
}