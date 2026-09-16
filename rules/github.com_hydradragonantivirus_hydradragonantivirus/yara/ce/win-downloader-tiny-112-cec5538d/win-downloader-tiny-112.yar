rule Win_Downloader_Tiny_112
{
strings:
	$a0 = { 57696e646f7773417070 }

	$a1 = { 53657475705f766572312e313531362e302e657865 }

	$a2 = { 5f5f5f646f5f736a6c6a5f696e6974 }


condition:
	$a0 and $a1 and $a2
}