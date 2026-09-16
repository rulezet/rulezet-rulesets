rule Win_Downloader_20397_1
{
strings:
	$a0 = { c745fc00000000c685d0f3ffff00b9ff01000033c08dbdd1f3fffff3ab66abaab90002000033c08dbdd0f3fffff3ab8d95d0f3ffffbf8031001083c9fff2aef7d12bf98bc18bf78bfac1e902f3a58bc883e103 }


condition:
	$a0
}