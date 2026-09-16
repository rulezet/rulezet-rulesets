rule Win_Trojan_Vulcan_3
{
strings:
	$a0 = { cd213c93745eb82135cd21891e21028c0623020e5848 }


condition:
	$a0
}