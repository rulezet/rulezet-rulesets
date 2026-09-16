rule Win_Trojan_IBV_1
{
strings:
	$a0 = { 8a042c302e8804494483f90075ef8be2c0e935302c }


condition:
	$a0
}