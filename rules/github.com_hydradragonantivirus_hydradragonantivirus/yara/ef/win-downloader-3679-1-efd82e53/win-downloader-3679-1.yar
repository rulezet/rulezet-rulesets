rule Win_Downloader_3679_1
{
strings:
	$a0 = { b8bc874000e8e4c2ffff6a03685c884000e8f4c3ffff }


condition:
	$a0
}