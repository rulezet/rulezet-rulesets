rule Win_Trojan_ExeHeader_5
{
strings:
	$a0 = { bb2000b44acd21b81335cd21ba4001b425cd218bd3bbae018c4f04061fb0cd }


condition:
	$a0
}