rule Win_Downloader_10116_1
{
strings:
	$a0 = { 68f4010000ff15383740006a00ff1510374000cc }


condition:
	$a0
}