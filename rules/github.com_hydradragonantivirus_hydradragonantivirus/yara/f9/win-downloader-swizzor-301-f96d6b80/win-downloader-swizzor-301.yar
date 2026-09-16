rule Win_Downloader_Swizzor_301
{
strings:
	$a0 = { e60a0182ffe5f05eb99417f896fcab5ba077a6d4b2b3c694d076164e25b289f81377c224565a885a4cb2cac8e68531ce }


condition:
	$a0
}