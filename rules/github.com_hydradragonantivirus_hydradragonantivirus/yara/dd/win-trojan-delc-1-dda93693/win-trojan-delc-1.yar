rule Win_Trojan_DelC_1
{
strings:
	$a0 = { 68ea0356f9db71ac19052200095d75c2 }


condition:
	$a0
}