rule Win_Downloader_Small_1263
{
strings:
	$a0 = { 68a41140006a00e889ffffff92906a006894114000e86bffff }


condition:
	$a0
}