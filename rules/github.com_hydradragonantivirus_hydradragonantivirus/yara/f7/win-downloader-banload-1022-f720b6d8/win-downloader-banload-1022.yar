rule Win_Downloader_Banload_1022
{
strings:
	$a0 = { d3f55107bb331a227bdaf67629f11afffe814b4dc05b0b013689f490704372d6dd8e41c995443c7e7b9754a8b166a0236bd62e5b }


condition:
	$a0
}