rule Win_Downloader_Small_1959
{
strings:
	$a0 = { 33c05050ff74241c5350e87b000000 }


condition:
	$a0
}