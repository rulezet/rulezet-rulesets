rule Win_Trojan_PowerPump_1
{
strings:
	$a0 = { 4552000d2025312025322025332025340d008db627 }


condition:
	$a0
}