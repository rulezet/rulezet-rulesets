rule Win_Downloader_35840_1
{
strings:
	$a0 = { 558bec81ec48020000[0-150]535353538d4dd851535356ffd0 }


condition:
	$a0
}