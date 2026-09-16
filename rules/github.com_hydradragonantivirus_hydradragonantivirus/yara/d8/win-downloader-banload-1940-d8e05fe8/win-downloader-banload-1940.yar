rule Win_Downloader_Banload_1940
{
strings:
	$a0 = { dca0c6770b7e422aba2b28241bd5169cda3a6c249c340720c1cbe6256c8e7cc24f85a38a6b3416cbd355c215512dffbc1bf717e1fed3e649e2a8bb28f45168475bd80fad6b08d1bd }


condition:
	$a0
}