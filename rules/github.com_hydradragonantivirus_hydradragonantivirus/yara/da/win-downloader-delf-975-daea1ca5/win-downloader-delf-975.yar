rule Win_Downloader_Delf_975
{
strings:
	$a0 = { 6a00a1b8e248008b00e8fc96f7ff50e802baf7ffa124e24800803800742ca1b8e248008b00e8e096f7ff506a01a1d4e048008b00e8d196f7ff8bc8bafcb74800b801000080e8f8bcfcff }


condition:
	$a0
}