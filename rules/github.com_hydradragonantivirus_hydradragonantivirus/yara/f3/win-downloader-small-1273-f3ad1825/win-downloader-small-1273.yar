rule Win_Downloader_Small_1273
{
strings:
	$a0 = { 558bec83c4f0b8c0104000e818ffffff6a006a006818114000683c1140006a00e883ffffff6a0068a4114000e87fffffffe8fafeffff }


condition:
	$a0
}