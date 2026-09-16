rule Win_Downloader_665_1
{
strings:
	$a0 = { 31ed81c5cb5c21f881c535653408558d9de8f2afff81c334125000bf01c8550089e151ff17b8ffdf11b12945008d6d0439dd7ee7c3 }


condition:
	$a0
}