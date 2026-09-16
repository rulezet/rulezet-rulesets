rule Win_Downloader_Bat_24
{
strings:
	$a0 = { 6f70656e20[0-45]62696e[0-10]67657420[0-50]2e657865[0-5]71756974 }


condition:
	$a0
}