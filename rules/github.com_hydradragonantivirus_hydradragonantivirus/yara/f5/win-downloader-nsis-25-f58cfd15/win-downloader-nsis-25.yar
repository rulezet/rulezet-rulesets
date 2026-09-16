rule Win_Downloader_NSIS_25
{
strings:
	$a0 = { 6c6f6164002f504f50555000fd99805cfd88802e65786500687474 }

	$a1 = { 7865266161613434343d7364 }


condition:
	$a0 and $a1
}