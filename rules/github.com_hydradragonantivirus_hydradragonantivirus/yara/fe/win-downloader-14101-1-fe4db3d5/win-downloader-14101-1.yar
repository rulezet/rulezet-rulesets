rule Win_Downloader_14101_1
{
strings:
	$a0 = { 8c747437667f5979f3fedceb96ba5337945135c56ce0924474c1fc98a69d70da8a853be1fcd4f84dc92c345dc9be1ab5747e394cbe763ec5e88ff4e167b84857 }


condition:
	$a0
}