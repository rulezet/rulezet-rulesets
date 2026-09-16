rule Win_Downloader_664_1
{
strings:
	$a0 = { 31ed81c5cb5c21????c535653408558d9de8f2afff81c3??125000bf01c8550089e151ff17b8ffdf11b12945008d6d0439dd7ee7c39b6d06bdc8de491c469251 }


condition:
	$a0
}