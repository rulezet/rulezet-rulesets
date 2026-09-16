rule Win_Trojan_Budo_2
{
strings:
	$a0 = { b97a03bf63048a0488054746e2f852b4408b1e0f01 }


condition:
	$a0
}