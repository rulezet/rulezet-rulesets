rule Win_Downloader_Small_2674
{
strings:
	$a0 = { 3333333333333333333307 }

	$a1 = { a7015607737663686f50742e6578e5c0e8ff88c0 }


condition:
	$a0 and $a1
}