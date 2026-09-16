rule Win_Downloader_Swizzor_323
{
strings:
	$a0 = { d22bfbfde71fd1b5adf3dae99dda5e2b160d1324f73d7601a229b0b4767f1aaf2d9465eb1550d7b515406a56f59af240 }


condition:
	$a0
}