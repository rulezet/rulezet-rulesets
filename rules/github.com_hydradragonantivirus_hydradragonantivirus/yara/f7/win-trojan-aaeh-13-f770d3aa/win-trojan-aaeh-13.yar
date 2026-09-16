rule Win_Trojan_AAEH_13
{
strings:
	$a0 = { 68636d71657478 }

	$a1 = { 701dfeffba848d40008d4de8e8631dfeffba749540008d4de8e8561dfeffba649d40008d4de8e8491dfeffba50a54000 }


condition:
	$a0 and $a1
}