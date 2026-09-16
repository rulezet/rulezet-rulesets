rule Win_Downloader_Small_1999
{
strings:
	$a0 = { 33dbf7f1535353530fb7c2ff348538104000ff152c104000 }


condition:
	$a0
}