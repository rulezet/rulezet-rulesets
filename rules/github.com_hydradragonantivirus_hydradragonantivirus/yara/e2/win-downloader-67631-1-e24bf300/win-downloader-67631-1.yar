rule Win_Downloader_67631_1
{
strings:
	$a0 = { 558bec83c4e033c08945e08945e48945ec8945e8b898271413 }

	$a1 = { 5061737331323334 }


condition:
	$a0 and $a1
}