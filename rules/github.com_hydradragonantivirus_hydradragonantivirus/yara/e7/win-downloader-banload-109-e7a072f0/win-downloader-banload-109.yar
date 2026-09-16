rule Win_Downloader_Banload_109
{
strings:
	$a0 = { af50194271bc635c5cef72e4e4b4227d99b78ced39966e7fba0391b97f0f24fff98876ac0000d4a074703a2f2f }


condition:
	$a0
}