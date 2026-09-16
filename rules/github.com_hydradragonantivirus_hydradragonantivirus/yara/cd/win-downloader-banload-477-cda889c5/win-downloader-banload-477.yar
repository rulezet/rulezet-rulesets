rule Win_Downloader_Banload_477
{
strings:
	$a0 = { 68386140008d8564ffffff50ff157050400068486140008d4d9651ff1570504000 }


condition:
	$a0
}