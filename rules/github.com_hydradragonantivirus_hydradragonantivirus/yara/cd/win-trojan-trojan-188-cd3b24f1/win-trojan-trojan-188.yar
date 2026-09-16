rule Win_Trojan_Trojan_188
{
strings:
	$a0 = { 01be6502a5a5a5a5a5a5161fba8000b41acd2158cb33c9ba320bb80143cd21 }


condition:
	$a0
}