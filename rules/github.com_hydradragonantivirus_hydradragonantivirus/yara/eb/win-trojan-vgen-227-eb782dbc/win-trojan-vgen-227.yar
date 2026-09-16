rule Win_Trojan_VGEN_227
{
strings:
	$a0 = { 030043cd20b801faba4559cd16e800005d81ed1100e894018db62f01bf0001a5a50e1f8d96bc01b41acd210e078d9e }


condition:
	$a0
}