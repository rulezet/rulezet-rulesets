rule Win_Downloader_Agent_32876
{
strings:
	$a0 = { c2e5a6a46c3d8e61b522b85f4e4aabf4140344328e36430352f6e14c032d9faaf5e9c06c81245c4c2f35e4387a2daaf51f30d8e55fa19f667634c6f0c01d }


condition:
	$a0
}