rule Win_Downloader_70310_1
{
strings:
	$a0 = { 68480500006840244000e80000471433f6c685a8 }

	$a1 = { 447a6e7673766333322e657865 }


condition:
	$a0 and $a1
}