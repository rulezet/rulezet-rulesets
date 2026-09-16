rule Win_Downloader_Small_1158
{
strings:
	$a0 = { 692d62696e2f66696c652e6367693f69643d383633343631202320416e6f6e69 }


condition:
	$a0
}