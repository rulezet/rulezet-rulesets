rule Win_Trojan_Sesc_1
{
strings:
	$a0 = { ee032e8b8492012ea300012e8b8494012ea30201b83f9ecd213d663f750b33f633ffb800015033c0c3b448bb1c00 }


condition:
	$a0
}