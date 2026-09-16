rule Win_Downloader_Small_2155
{
strings:
	$a0 = { 558bec81ec58010000568d85a8feffff506804010000ff150c10400068??1040008d85a8feffff50ff1508104000be48104000eb0b }


condition:
	$a0
}