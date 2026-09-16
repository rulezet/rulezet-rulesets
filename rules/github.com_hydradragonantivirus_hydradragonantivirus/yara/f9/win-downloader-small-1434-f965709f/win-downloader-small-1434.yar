rule Win_Downloader_Small_1434
{
strings:
	$a0 = { 302e31310000002575000063632e61642d776172 }


condition:
	$a0
}