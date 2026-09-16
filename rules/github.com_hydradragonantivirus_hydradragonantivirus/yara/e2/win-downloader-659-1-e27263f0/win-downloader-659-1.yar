rule Win_Downloader_659_1
{
strings:
	$a0 = { 83caff425252be????5500ff1609c0752e89c281c2cb4c??f081c23565ff0f8d8a3cf5ffff81c1001000005205f0dfafb12902832a0f31c08d520439ca7eedbe }


condition:
	$a0
}