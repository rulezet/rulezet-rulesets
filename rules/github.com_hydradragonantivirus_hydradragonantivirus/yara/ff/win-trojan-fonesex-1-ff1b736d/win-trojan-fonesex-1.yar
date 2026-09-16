rule Win_Trojan_FoneSex_1
{
strings:
	$a0 = { 079000b43bcd21c3e89b00e89f00 }


condition:
	$a0
}