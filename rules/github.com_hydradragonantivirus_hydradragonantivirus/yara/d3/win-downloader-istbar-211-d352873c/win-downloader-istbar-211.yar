rule Win_Downloader_Istbar_211
{
strings:
	$a0 = { 3026b2758e66cf11 }

	$a1 = { 27000000687474703a2f2f64726d2e7973627765622e636f6d }


condition:
	$a0 and $a1
}