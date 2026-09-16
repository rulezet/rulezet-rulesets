rule Win_Downloader_Tibs_2
{
strings:
	$a0 = { d9f1d9fcd9cbd9ea }


condition:
	$a0
}