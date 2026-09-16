rule Win_Trojan_CryptMBR_1
{
strings:
	$a0 = { 7db90100ba8000bb3301cd13b900fa8bf98a85330134ff88853301e2f2b403b07db90100ba8000bb3301cd13b44ccd21 }


condition:
	$a0
}