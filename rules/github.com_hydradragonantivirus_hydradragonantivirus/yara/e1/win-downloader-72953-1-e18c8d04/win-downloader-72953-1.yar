rule Win_Downloader_72953_1
{
strings:
	$a0 = { 505657f85253510f83c1ffffff10626a691e1654d68e }

	$a1 = { b208492851784e56540df3 }

	$a2 = { 504f5354 }


condition:
	$a0 and $a1 and $a2
}