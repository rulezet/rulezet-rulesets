rule Win_Trojan_Murphy_12
{
strings:
	$a0 = { b84d4bcd217203e926015e568bfe33c0 }


condition:
	$a0
}