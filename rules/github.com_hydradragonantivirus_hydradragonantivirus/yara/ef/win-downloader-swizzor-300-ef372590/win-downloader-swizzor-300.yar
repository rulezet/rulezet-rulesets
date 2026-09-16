rule Win_Downloader_Swizzor_300
{
strings:
	$a0 = { 28a62fcf06c1c5a2d52207a44b8ed44aefce33a2e558e3a4c9295851710e22de49fca44d3a7b844186bc303efce5f390 }


condition:
	$a0
}