rule Win_Trojan_Dauq_4
{
strings:
	$a0 = { 5d55be03012bee03f58bfe2e8c9e680afc0e1f0e07b94c00ac0401aae2fac3 }


condition:
	$a0
}