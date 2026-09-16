rule Win_Trojan_Linda_2
{
strings:
	$a0 = { 80f11d741c5006e8b3ff26813d434f0758740e0e1fb440b90502ba0001cd210e1fb8015759 }


condition:
	$a0
}