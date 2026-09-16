rule Win_Downloader_Swizzor_291
{
strings:
	$a0 = { 8e9d5757db146e3c470af6d89812deabe2796251434948afcdb897f2e326ce5baf4fac976caf15199604941d48943db8 }


condition:
	$a0
}