rule Win_Downloader_60794_1
{
strings:
	$a0 = { 558bec6aff68a8304000682020400064a10000000050648925000000 }

	$a1 = { 6e65776b657939 }


condition:
	$a0 and $a1
}