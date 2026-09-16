rule Win_Trojan_ExeHeader_2
{
strings:
	$a0 = { 500e0e1f07bf2400e80400eb17909a8a260e00be2400b9dc00ac32c4aae2fac3 }


condition:
	$a0
}