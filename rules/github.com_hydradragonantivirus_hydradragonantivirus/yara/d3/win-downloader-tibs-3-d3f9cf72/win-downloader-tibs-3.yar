rule Win_Downloader_Tibs_3
{
strings:
	$a0 = { 8d00dde7d9ecb800a2400031d2d9ea }


condition:
	$a0
}