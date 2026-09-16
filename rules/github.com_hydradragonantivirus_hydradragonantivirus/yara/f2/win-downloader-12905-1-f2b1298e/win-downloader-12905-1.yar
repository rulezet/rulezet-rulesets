rule Win_Downloader_12905_1
{
strings:
	$a0 = { 8bc0b84d16400083f00c83f00c8bf883c728558bec53b8cc224000be121740002bf78bce51578bd8508bc0e8fe000000 }


condition:
	$a0
}