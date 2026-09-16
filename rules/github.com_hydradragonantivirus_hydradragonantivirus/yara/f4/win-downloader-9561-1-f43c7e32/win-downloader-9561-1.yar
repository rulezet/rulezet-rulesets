rule Win_Downloader_9561_1
{
strings:
	$a0 = { 558bec83ec5868504a14136898461413e830040000 }


condition:
	$a0
}