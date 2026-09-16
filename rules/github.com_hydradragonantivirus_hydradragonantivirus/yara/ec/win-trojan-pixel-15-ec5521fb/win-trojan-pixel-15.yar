rule Win_Trojan_Pixel_15
{
strings:
	$a0 = { ba9e00b8023dcd218bd8061fba1b01 }


condition:
	$a0
}