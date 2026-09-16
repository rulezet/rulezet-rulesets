rule Win_Downloader_Banload_1939
{
strings:
	$a0 = { c61f8834c37dc425c0a5df43dfdca0c6770b7e422aba2b28241bd5169cda3a6c249c340720c1cbe6256c8e7cc24f85a38a6b3416cbd355c215512dffbc1bf717e1fed3e649e2a8bb }


condition:
	$a0
}