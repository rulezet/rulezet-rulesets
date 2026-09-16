rule Win_Downloader_51078_1
{
strings:
	$a0 = { 5c89441108ff45dcebdbe898b8 }

	$a1 = { 2e6d6978637274 }

	$a2 = { 626b28736668287362702873626e28737269 }


condition:
	$a0 and $a1 and $a2
}