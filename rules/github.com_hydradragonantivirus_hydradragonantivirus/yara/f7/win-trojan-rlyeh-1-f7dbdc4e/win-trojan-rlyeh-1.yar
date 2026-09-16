rule Win_Trojan_Rlyeh_1
{
strings:
	$a0 = { be06018bfeb9????ad35????abe2f9c3 }


condition:
	$a0
}