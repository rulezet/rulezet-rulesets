rule Win_Trojan_Quake_3
{
strings:
	$a0 = { 5d81ed03018db6d702bf000057a5a48bfd8bec81ec8000b42fcd2153b41a8d5680cd21b9eb09b805feebfc80c43b }


condition:
	$a0
}