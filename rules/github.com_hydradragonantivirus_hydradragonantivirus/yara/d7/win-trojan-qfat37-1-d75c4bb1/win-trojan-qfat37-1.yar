rule Win_Trojan_QFat37_1
{
strings:
	$a0 = { b43fb90002ba3603cd21b43ecd21b403b001b500b1018a3646058a164505bb3603cd137205eb }


condition:
	$a0
}