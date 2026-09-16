rule Win_Downloader_Delf_1127
{
strings:
	$a0 = { e8d5b8ffff8b45e8e8ddb9ffff50a1aca84000e8d2b9ffff506a00e8b2c6ffff }


condition:
	$a0
}