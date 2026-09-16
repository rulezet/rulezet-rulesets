rule Win_Trojan_Tver_4
{
strings:
	$a0 = { bda10d85e99f751b9c9a82af5c1244589a189c83749c9cc2b21018689db215186e9d9b8228d551bd }


condition:
	$a0
}