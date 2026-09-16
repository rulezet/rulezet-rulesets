rule Win_Trojan_TPVO_13
{
strings:
	$a0 = { b91f05cd12be12002e803400cd1246e2f7 }


condition:
	$a0
}