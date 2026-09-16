rule Win_Trojan_Pakes_994
{
strings:
	$a0 = { 6033c02d9493ffff502d0909d29b502df800caea508bc46a006a0050e8 }


condition:
	$a0
}