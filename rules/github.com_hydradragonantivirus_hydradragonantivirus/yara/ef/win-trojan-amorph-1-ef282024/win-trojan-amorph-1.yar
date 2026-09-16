rule Win_Trojan_AMorph_1
{
strings:
	$a0 = { 25cd210e1f0e07b41791b4572ae55a595bcd00b43fbe }


condition:
	$a0
}