rule Win_Downloader_Banload_96
{
strings:
	$a0 = { 84c07421b8a8a74000ba64824000e8b0b4ffff6a00a1a8a74000e820b8ffff50e842c4ffff }


condition:
	$a0
}