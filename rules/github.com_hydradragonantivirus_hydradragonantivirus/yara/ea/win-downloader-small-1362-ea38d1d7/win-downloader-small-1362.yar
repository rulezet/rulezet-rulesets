rule Win_Downloader_Small_1362
{
strings:
	$a0 = { 646c6c002e006d6f6e0075726c004100 }


condition:
	$a0
}