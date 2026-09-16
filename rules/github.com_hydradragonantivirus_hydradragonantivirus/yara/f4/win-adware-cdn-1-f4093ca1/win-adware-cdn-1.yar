rule Win_Adware_CDN_1
{
strings:
	$a0 = { 434e4e49435c43646e00558bec83ec0c53 }


condition:
	$a0
}