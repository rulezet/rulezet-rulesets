rule Win_Trojan_Frisk_8
{
strings:
	$a0 = { 8bfc368b2d81ed03012e803e2d01b97427b998038dbe2d01ba0100 }


condition:
	$a0
}