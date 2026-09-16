rule Win_Downloader_Monurl_5
{
strings:
	$a0 = { 687474703a2f2f }

	$a1 = { 646c6c002e006d6f6e0075726c00410046696c6500546f00446f776e6c6f61640055524c }


condition:
	$a0 and $a1
}