rule Win_Trojan_Peed_254
{
strings:
	$a0 = { 8d1d940c220068395c1a00435fc1d1586812fa4202415b84ca8d35843d4000f8 }


condition:
	$a0
}