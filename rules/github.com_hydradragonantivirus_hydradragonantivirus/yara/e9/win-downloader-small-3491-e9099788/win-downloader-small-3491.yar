rule Win_Downloader_Small_3491
{
strings:
	$a0 = { e8000000005a81c26f830000ffe2 }


condition:
	$a0
}