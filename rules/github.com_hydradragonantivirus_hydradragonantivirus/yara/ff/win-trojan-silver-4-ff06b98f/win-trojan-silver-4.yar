rule Win_Trojan_Silver_4
{
strings:
	$a0 = { ded1e3ffb73305e84501594683fe127ceeb8b30850b807 }


condition:
	$a0
}