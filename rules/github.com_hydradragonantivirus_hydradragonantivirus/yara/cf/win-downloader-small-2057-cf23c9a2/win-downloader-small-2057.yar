rule Win_Downloader_Small_2057
{
strings:
	$a0 = { 46c7687411703a2fc575d46461c63a2e6d34ce30734f }


condition:
	$a0
}