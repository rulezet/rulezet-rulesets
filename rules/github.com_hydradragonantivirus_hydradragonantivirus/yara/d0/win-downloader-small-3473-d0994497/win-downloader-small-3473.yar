rule Win_Downloader_Small_3473
{
strings:
	$a0 = { 83c40c68600240008d8560feffff50ffd78d8560feffff686802400050e889010000 }


condition:
	$a0
}