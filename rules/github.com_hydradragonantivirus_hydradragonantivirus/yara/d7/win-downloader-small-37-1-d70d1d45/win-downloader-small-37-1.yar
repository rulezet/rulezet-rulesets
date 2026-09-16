rule Win_Downloader_Small_37_1
{
strings:
	$a0 = { 2f322e657865000000ffffffff0a000000686f737434322e65786500 }


condition:
	$a0
}