rule Win_Downloader_Small_1628
{
strings:
	$a0 = { d8478fb7d3c7056b0070bd6aeea78e6fabcacb61 }


condition:
	$a0
}