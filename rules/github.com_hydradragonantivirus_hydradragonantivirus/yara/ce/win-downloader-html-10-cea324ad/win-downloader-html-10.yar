rule Win_Downloader_HTML_10
{
strings:
	$a0 = { 434f4445424153453d27[0-16]2e7478742e657865273e3c2f6f626a6563743e }


condition:
	$a0
}