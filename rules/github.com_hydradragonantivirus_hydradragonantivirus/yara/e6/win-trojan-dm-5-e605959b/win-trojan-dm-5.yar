rule Win_Trojan_DM_5
{
strings:
	$a0 = { 16b93701be25155080340c46e2fac3 }


condition:
	$a0
}