rule Win_Trojan_Nympho_4
{
strings:
	$a0 = { 0e1f072efe0619012ea12001be2201bf2201b97802ac2fe0aae2faeb02 }


condition:
	$a0
}