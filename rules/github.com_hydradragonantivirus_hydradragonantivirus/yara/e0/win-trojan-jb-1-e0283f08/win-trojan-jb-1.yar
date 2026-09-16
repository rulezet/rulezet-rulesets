rule Win_Trojan_JB_1
{
strings:
	$a0 = { 0b05d2007303b8ffffa3e50bb800428bd633c9e8c7fde81600b440bad90bb94000e8b9fdff06 }


condition:
	$a0
}