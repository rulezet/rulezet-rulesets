rule Win_Downloader_Small_2022
{
strings:
	$a0 = { 558bec81c4a0f8ffff6a006a0168da200010e8a90200000bc07502 }


condition:
	$a0
}