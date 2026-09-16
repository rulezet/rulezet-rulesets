rule Win_Downloader_Small_3387
{
strings:
	$a0 = { bbbf21400081eb10204000b910204000ebc868552240006a006800000200e8 }


condition:
	$a0
}