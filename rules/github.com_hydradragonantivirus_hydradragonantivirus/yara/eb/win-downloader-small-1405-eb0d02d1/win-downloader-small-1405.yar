rule Win_Downloader_Small_1405
{
strings:
	$a0 = { 68903200118b4508ffb084000000e8c4b1ffff8bd08d4d9ce8bcb2ffff5068f8320011e8afb1ffff8bd08d4d98e8a7b2ffff508b4508ff7054e899b1ffff }


condition:
	$a0
}