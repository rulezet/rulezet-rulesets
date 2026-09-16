rule Win_Downloader_681_1
{
strings:
	$a0 = { 909ee154d208e72600c870631b6e695da704dcd34180586789fcbf1d7cbf8131c7d3a2673e758d67034ae54c913776546430d2e0acece6e4ec1ed409fa5dfae5 }


condition:
	$a0
}