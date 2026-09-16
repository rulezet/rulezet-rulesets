rule Win_Trojan_Ascii_218_38_12_110_1
{
strings:
	$a0 = { 3231382e33382e31322e313130 }


condition:
	$a0
}