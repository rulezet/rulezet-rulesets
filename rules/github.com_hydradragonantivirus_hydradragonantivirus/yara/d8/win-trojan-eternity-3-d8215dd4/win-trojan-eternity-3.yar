rule Win_Trojan_Eternity_3
{
strings:
	$a0 = { e800005d83ed03e81500eb2790e80f00b440b935028bd5cd }


condition:
	$a0
}