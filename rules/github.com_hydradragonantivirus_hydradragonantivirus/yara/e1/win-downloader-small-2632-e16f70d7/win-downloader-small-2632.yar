rule Win_Downloader_Small_2632
{
strings:
	$a0 = { f3a451515368a303400051e83d000000 }


condition:
	$a0
}