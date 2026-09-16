rule Win_Downloader_Adload_13
{
strings:
	$a0 = { 8bd08d4dace86becffffba581c40008d4db0e888ecffffbae41b40008d4db4e87becffff }


condition:
	$a0
}