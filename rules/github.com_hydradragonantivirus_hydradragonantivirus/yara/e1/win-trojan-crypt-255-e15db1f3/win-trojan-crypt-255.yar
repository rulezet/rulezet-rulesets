rule Win_Trojan_Crypt_255
{
strings:
	$a0 = { 558bec6aff68[0-1]31400068[0-2]400064a10000000050648925 }

	$a1 = { 5c7368656c6c65786563757465686f6f6b73 }


condition:
	$a0 and $a1
}