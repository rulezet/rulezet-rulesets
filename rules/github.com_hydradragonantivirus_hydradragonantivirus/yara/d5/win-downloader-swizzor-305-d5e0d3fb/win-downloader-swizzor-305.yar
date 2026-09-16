rule Win_Downloader_Swizzor_305
{
strings:
	$a0 = { 66df20cb2d3e2b890210f800d9b5bd1496064c19d2b7bee9b16bfaf4d58351fdf0ad7184f081d5fe0f3a6268d8e16f81 }


condition:
	$a0
}