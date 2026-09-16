rule Win_Downloader_Swizzor_267
{
strings:
	$a0 = { e0e72667d595ca101e788844842e6dcb797c1fbcd2f5078aa7c99be9358bb4650ae64dd47694aa5ac037b55af32896bd }


condition:
	$a0
}