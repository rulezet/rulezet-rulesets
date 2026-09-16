rule Win_Downloader_67636_1
{
strings:
	$a0 = { e82000000043006700c4ee00bf00b2d9000047 }

	$a1 = { 791b1b2d2c213b }


condition:
	$a0 and $a1
}