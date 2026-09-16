rule Win_Trojan_Ohio_3
{
strings:
	$a0 = { 2128bb007eb80602cd13597302e2e7c3 }


condition:
	$a0
}