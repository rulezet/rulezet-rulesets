rule Win_Trojan_XTC_1
{
strings:
	$a0 = { b968f78bd981c1ea1081c3ae0881376ef743e2f9 }


condition:
	$a0
}