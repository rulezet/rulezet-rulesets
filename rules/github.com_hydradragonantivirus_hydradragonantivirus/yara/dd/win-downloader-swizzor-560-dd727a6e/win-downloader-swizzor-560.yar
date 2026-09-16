rule Win_Downloader_Swizzor_560
{
strings:
	$a0 = { 3e3052d5f9b163048cb46cfc5a51f4e8bb6dba69e88335d57f4a458e085594e2ba7445f656feb6bf40ca6564279c356120b9dfeee9fa16120621e067dbf0ee8871cfa5ee869b70a44ec0a9b7 }


condition:
	$a0
}