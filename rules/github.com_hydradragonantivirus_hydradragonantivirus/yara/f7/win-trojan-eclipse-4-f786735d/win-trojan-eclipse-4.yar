rule Win_Trojan_Eclipse_4
{
strings:
	$a0 = { 33c0fa8ed0bc007cfb8ed8ff0e1304a11304c1e0068ec033ffb90002be007cfcf3a4b80102bb0002e8??00 }


condition:
	$a0
}