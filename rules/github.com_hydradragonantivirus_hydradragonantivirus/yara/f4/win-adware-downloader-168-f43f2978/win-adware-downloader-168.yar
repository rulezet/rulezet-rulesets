rule Win_Adware_Downloader_168
{
strings:
	$a0 = { 636e65742e636f6d2f752f646c6d[5-20]6f666665725f[1-10]2e646c6c }


condition:
	$a0
}