rule Win_Trojan_Nocopy_1
{
strings:
	$a0 = { 33c08ed0bc007c8ec08ed8be4c00bff804b0eafcaaadabadabfabe007cbf0006b90001f2a5ea2b060000bebe }


condition:
	$a0
}