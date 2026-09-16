rule Win_Downloader_61073_1
{
strings:
	$a0 = { 7969686168612e6578650000ffffffff07000000687474703a2f2f }


condition:
	$a0
}