rule Win_Trojan_VS_1
{
strings:
	$a0 = { b43fb5ffcd2150803e7a01b87414b8004233c933d2cd21595183c17afec6b440cd21 }


condition:
	$a0
}