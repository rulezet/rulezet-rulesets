rule Win_Trojan_VS_3
{
strings:
	$a0 = { b9be0690b440e8f7025a5872cf813e6c074d5a740ec7066c07e9002d0300a36d07eb3a5052 }


condition:
	$a0
}