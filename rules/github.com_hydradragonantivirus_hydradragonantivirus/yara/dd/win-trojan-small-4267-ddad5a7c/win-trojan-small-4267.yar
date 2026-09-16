rule Win_Trojan_Small_4267
{
strings:
	$a0 = { e833ffffff6a00e819000000cc }


condition:
	$a0
}