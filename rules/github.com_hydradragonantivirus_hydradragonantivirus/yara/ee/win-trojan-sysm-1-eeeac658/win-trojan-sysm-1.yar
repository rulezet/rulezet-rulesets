rule Win_Trojan_SysM_1
{
strings:
	$a0 = { 408bd583ea04b95c019c3eff9ee70072a4b8004233c98bd19c3eff9ee700b4408bd581c27501b9 }


condition:
	$a0
}