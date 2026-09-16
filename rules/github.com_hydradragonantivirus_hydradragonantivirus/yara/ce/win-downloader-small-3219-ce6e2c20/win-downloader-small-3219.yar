rule Win_Downloader_Small_3219
{
strings:
	$a0 = { 27b5507b702a2eaf3c52a991e1264f5bf7e8745261f28f5170edb9a372a7b06376bfba515712cc36bf2fb2a276a5a34354b7c0de97bef4bc53dc92a276264452e4bebaa255b9 }


condition:
	$a0
}