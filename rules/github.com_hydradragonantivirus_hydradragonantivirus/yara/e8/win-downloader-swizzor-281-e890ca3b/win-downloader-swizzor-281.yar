rule Win_Downloader_Swizzor_281
{
strings:
	$a0 = { 5fdf2404f93adc340ff66beee780457b5404a421ee37c1d7970d70c002ee56185999c21f52c91e033fb4dbb133e8f9d7 }


condition:
	$a0
}