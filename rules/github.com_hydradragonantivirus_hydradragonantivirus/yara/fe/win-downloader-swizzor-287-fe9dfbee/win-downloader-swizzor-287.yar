rule Win_Downloader_Swizzor_287
{
strings:
	$a0 = { 10d0e51424fcaf14321275b8ce343d36395137eed176169c64adaa30ab6a1b482ffc1fea4eedaa0a62863fe19f4158974ccf86d1e0453a6b5879a41688f46ffe27818dfea8b22bcf592d1e9b }


condition:
	$a0
}