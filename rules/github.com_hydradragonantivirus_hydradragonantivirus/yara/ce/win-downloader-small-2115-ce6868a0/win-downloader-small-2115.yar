rule Win_Downloader_Small_2115
{
strings:
	$a0 = { 6a00be383040006a005668103040006a00e80e00000056ff1510204000 }


condition:
	$a0
}