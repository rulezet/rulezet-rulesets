rule Win_Trojan_Trojan_283
{
strings:
	$a0 = { ba9e00cd21720f93ba0001b440b92d00cd21b43ecd21b44f }


condition:
	$a0
}