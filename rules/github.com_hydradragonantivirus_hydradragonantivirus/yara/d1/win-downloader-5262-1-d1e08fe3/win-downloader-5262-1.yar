rule Win_Downloader_5262_1
{
strings:
	$a0 = { 6a0759be003214138dbd8cfefffff3a566a5a46a0759bee03114138dbdacfefffff3a566a5a46a0859bebc3114138dbd44fefffff3a566a5a46a0859be983114138dbd68fefffff3a566a5a4 }


condition:
	$a0
}