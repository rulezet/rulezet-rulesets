rule Win_Downloader_Bat_22
{
strings:
	$a0 = { 6f70656e20[0-25]7573657220[0-60]67657420[0-50]2e657865[0-5]627965 }


condition:
	$a0
}