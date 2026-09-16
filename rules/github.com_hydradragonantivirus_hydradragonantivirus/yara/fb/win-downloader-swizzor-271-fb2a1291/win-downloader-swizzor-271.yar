rule Win_Downloader_Swizzor_271
{
strings:
	$a0 = { ec4c55ead2fac6c8c4b336b848e4fa80a8de97c4adffd3250973bd2c491b0ac4285b07079e9dbeca950583a390987f61 }


condition:
	$a0
}