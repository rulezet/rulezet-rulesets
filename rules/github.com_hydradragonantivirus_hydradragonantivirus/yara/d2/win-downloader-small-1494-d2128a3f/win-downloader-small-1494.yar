rule Win_Downloader_Small_1494
{
strings:
	$a0 = { 0f848f000000bfe091400083c9ff33c08d542474f2ae }


condition:
	$a0
}