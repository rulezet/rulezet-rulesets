rule Win_Trojan_Jerkin_2
{
strings:
	$a0 = { cd1a89964c01b41a8d964e01cd21bf00018db68300a5a5a5c6865f002ac68660002ee83b00 }


condition:
	$a0
}