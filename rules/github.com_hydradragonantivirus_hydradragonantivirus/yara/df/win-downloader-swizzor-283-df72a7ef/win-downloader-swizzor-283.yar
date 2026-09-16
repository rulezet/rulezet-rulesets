rule Win_Downloader_Swizzor_283
{
strings:
	$a0 = { 7ee984d18049a7c9c689388367c51be24d3acbf2ef02928285571a75fe3a61db0d0e7d2367d29edca67059c3e733aa57 }


condition:
	$a0
}