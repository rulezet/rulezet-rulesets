rule Win_Downloader_6814_1
{
strings:
	$a0 = { b8b4a74000ba??804000e81ab7ffff }


condition:
	$a0
}