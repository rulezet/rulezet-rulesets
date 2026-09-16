rule Win_Downloader_Small_1820
{
strings:
	$a0 = { 10505c646c6c7379732e06120494841fc8a88aca0cf21c4505 }


condition:
	$a0
}