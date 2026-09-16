rule Win_Trojan_DarthVader_13
{
strings:
	$a0 = { c08ed88e06ae00b800908ed831ff4781ff000f77585731 }


condition:
	$a0
}