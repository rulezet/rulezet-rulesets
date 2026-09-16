rule Win_Trojan_TBS_1
{
strings:
	$a0 = { b83400cdadcd94cd817403e90d00cd3b067401b84500cdeca0cd81cd3b067001b85800cdeca0 }


condition:
	$a0
}