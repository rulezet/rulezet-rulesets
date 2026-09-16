rule Win_Downloader_Small_2601
{
strings:
	$a0 = { 6830304000e88c01000050bb61304000435350e86c010000 }


condition:
	$a0
}