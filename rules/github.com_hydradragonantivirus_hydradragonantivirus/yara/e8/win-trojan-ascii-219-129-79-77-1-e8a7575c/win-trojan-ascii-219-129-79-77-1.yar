rule Win_Trojan_Ascii_219_129_79_77_1
{
strings:
	$a0 = { 3231392e3132392e37392e3737 }


condition:
	$a0
}