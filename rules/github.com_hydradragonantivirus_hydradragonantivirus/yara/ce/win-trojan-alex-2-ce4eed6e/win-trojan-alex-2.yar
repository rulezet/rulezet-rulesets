rule Win_Trojan_Alex_2
{
strings:
	$a0 = { bf00018db64a03b90300f3a4c6865a0300c6865b0300e80b }


condition:
	$a0
}