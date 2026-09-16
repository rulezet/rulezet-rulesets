rule Win_Downloader_Dadobra_122
{
strings:
	$a0 = { a1e80e45008b00ba20f14400e81904a5f08b0dc00f4500a1e80e45008b008b15c8e34400e81904a9e4 }


condition:
	$a0
}