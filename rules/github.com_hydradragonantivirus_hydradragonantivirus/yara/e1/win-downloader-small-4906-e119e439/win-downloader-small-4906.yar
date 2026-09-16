rule Win_Downloader_Small_4906
{
strings:
	$a0 = { 622e6a70670000ffffffff070000005c55706461746500ffffffff0a0000005c49736173732e7363720000ffffffff }


condition:
	$a0
}