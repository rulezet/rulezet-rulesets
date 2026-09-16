rule Win_Trojan_FormatC_3
{
strings:
	$a0 = { 4d4154000420633a0d008db62000bf0100b82801ffd08db637008dbe3f00b85603ffd0b800 }


condition:
	$a0
}