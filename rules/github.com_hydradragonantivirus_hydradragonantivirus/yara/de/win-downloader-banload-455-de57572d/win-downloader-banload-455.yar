rule Win_Downloader_Banload_455
{
strings:
	$a0 = { ba78c94400b890c94400e851ffffff84c07414 }


condition:
	$a0
}