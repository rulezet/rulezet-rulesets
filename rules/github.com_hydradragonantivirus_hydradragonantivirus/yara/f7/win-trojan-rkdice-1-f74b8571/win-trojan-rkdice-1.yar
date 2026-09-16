rule Win_Trojan_RkDice_1
{
strings:
	$a0 = { 55545d6affe932fcffffe804210000e8010a00008bc8e86fd400005059e91dfdffff }


condition:
	$a0
}