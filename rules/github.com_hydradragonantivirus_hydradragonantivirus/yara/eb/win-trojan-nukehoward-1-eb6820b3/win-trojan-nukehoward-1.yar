rule Win_Trojan_NukeHoward_1
{
strings:
	$a0 = { 575552b8fe05babaa6f7d0f7d2cd16b8fd05babaa6b80000f7d0f7d2cd165a5d5fe90000e800005d81ed27018db64e04bf0001939357a5a48bfd549c555752e8 }


condition:
	$a0
}