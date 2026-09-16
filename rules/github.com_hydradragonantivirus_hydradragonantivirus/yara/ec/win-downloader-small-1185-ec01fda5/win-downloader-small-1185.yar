rule Win_Downloader_Small_1185
{
strings:
	$a0 = { 742e636f97b0ffff6d2f332f77696e33327362642e657865000c7fac7b0f482d1a114003092001019049 }


condition:
	$a0
}