rule Win_Downloader_5467_1
{
strings:
	$a0 = { 81ec0401000053555657be301640006a028bdeff154010400050ff153c104000 }


condition:
	$a0
}