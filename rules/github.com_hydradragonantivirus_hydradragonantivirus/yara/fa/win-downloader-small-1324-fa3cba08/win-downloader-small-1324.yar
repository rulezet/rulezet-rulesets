rule Win_Downloader_Small_1324
{
strings:
	$a0 = { 3f5827205c6d3f73316ea4547415686fce7de7b2be195cac0d10702861796c89165c590d0c3073 }


condition:
	$a0
}