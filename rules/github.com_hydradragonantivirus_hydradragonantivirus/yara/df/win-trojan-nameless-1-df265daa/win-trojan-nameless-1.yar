rule Win_Trojan_Nameless_1
{
strings:
	$a0 = { 01b97f0b8a242ae232e6882446fec6fec2fec6e2efc3 }


condition:
	$a0
}