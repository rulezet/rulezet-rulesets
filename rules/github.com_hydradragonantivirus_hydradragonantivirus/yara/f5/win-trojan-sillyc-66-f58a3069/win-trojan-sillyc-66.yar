rule Win_Trojan_SillyC_66
{
strings:
	$a0 = { fc33db8bbf010183c703578db5a101bf0001f3a45fb920008d959b01b44ecd21720ee81000b44fcd217205e807 }


condition:
	$a0
}