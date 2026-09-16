rule Win_Trojan_VGEN_500
{
strings:
	$a0 = { dc01bf0001a5a5a5a45f8bec81ec8000b42fcd2153b41a8d5680cd21e8c5013d0b00750ee8c5 }


condition:
	$a0
}