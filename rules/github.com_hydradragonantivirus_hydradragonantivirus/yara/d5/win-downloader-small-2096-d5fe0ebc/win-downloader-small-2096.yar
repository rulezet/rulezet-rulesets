rule Win_Downloader_Small_2096
{
strings:
	$a0 = { 33c05050ff742410ff74241050e814000000c3 }


condition:
	$a0
}