rule Win_Trojan_Brat_2
{
strings:
	$a0 = { 69732069732061206a6f6b652066696c65206279206a61636b2e000055aa }


condition:
	$a0
}