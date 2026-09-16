rule Win_Trojan_Kuku_3
{
strings:
	$a0 = { ba8b02b9310090b440cd217213b8 }


condition:
	$a0
}