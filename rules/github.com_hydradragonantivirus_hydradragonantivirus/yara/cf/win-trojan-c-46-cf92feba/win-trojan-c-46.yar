rule Win_Trojan_C_46
{
strings:
	$a0 = { c3ba1401b90000b43ccd21725f8bd8b9c603ba0001b440cd21b43ecd21ba1401b90300b801 }


condition:
	$a0
}