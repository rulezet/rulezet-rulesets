rule Win_Downloader_Small_2452
{
strings:
	$a0 = { 23703a2f8838312e393935f5313436083332fc64653e5f6cf47678e18302633a5c62 }


condition:
	$a0
}