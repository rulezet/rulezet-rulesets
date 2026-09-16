rule Win_Downloader_67685_1
{
strings:
	$a0 = { 558bec538b5d08568b750c578b7d1085 }

	$a1 = { 66696e647870726f706f7274616c312e636f6d }

	$a2 = { 4765636b6f2f32303037 }


condition:
	$a0 and $a1 and $a2
}