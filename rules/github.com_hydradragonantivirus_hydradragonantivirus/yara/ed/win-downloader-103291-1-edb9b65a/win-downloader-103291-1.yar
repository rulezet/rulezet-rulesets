rule Win_Downloader_103291_1
{
strings:
	$a0 = { 5781ec000200008bfc6a7857e8????????8d4f7c33d252525251525703f8b85c6d6369 }


condition:
	$a0
}