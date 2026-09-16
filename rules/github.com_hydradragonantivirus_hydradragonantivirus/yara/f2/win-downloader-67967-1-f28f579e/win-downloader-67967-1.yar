rule Win_Downloader_67967_1
{
strings:
	$a0 = { 558bec6aff683083400068ac5840 }

	$a1 = { 2f6275792e706870 }

	$a2 = { 2f646f776e6c6f61642e706870 }


condition:
	$a0 and $a1 and $a2
}