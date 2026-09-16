rule Win_Downloader_Delf_957
{
strings:
	$a0 = { b8b0984000ba??7f4000e894b7ffffb8ac984000????b7ffffb8b49840008b15b0984000e8??b7ffff68fe00000068a8974000e8??c6ffff }


condition:
	$a0
}