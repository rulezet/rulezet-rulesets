rule Win_Downloader_Cryptex_1
{
strings:
	$a0 = { 68d4420eb50e3d327b7f0f1428680cfa32a907267fa119f68629137918a42b38854a6d3950f75d5b2881c4f793713c04ea1a417f60fe51be5a }


condition:
	$a0
}