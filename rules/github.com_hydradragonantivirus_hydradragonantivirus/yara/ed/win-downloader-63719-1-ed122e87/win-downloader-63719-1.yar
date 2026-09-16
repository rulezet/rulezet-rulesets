rule Win_Downloader_63719_1
{
strings:
	$a0 = { 60be00b041008dbe0060feff5789e58d9c2480c1ffff31c05039dc75fb464653686a5e02 }


condition:
	$a0
}