rule Win_Downloader_Small_1779
{
strings:
	$a0 = { 44006a006a00e8e477fdffa1dcef44008b00e80ce7ffffe86f72fbff0000005354464b204d75746578587800000000ffffffff10000000633a5c }


condition:
	$a0
}