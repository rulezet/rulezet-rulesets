rule Win_Downloader_11684_1
{
strings:
	$a0 = { 87d187d19090909051575f59 }


condition:
	$a0
}