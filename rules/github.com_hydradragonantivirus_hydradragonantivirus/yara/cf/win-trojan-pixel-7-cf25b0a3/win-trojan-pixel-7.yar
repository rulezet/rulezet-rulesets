rule Win_Trojan_Pixel_7
{
strings:
	$a0 = { b9ffffb43fcd2105f7042ea35e018bf283c603ac3c257503eb229033c98bd12e8b1e6001b8 }


condition:
	$a0
}