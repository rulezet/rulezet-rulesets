rule Win_Downloader_Small_1371
{
strings:
	$a0 = { 78656300687474703a2f2f7777772e3136336376 }


condition:
	$a0
}