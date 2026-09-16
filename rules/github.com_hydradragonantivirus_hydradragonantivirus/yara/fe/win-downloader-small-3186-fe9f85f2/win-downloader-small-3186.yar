rule Win_Downloader_Small_3186
{
strings:
	$a0 = { 79686bfd72e7ba6cba6d3d01df5e3868748e703a2f2877072e616ecfce6f8379666c7b1263 }


condition:
	$a0
}