rule Win_Downloader_BAT_107
{
strings:
	$a0 = { 667470202d6e202d76202d733a[0-1]2e706966 }


condition:
	$a0
}