rule Win_Downloader_Swizzor_317
{
strings:
	$a0 = { c048056aa21051a42eff038cff11b857c28a183de98ad5c61bfe065aa16d5c6dc80cf77c6a04e7cbe627b1a65fc8cc72 }


condition:
	$a0
}