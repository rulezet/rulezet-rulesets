rule Win_Trojan_7son_1
{
strings:
	$a0 = { b9b8018bd6cd21721f33d233c9b80042cd2172142ea19a00c7054de9894502b440b904008bd7 }


condition:
	$a0
}