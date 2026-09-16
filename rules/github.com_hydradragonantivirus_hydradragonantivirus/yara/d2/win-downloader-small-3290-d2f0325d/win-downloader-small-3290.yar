rule Win_Downloader_Small_3290
{
strings:
	$a0 = { 6068ffffff015931c040410fa285c274100f50d089d00f50cbf30f5ed8f30f5ccb }


condition:
	$a0
}