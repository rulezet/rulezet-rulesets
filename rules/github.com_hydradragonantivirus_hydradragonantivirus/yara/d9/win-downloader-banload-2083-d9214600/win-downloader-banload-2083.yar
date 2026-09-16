rule Win_Downloader_Banload_2083
{
strings:
	$a0 = { 558becb81e4c5581bb9309549c50e800000000582da81a0000b96d1a0000ba211b0000be }


condition:
	$a0
}