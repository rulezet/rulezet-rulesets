rule Win_Downloader_Small_1660
{
strings:
	$a0 = { 6c6d2a6e2aed5b016092524c446f7f774b6c83af54c4b8edd046ec6871741c703a2f466c69661c6f6b52032e63 }


condition:
	$a0
}