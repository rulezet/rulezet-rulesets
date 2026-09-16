rule Win_Trojan_SumsDos_1
{
strings:
	$a0 = { b8ff00509a2d055302c606df075ac6064400e9c606450092c606460000c606470073 }


condition:
	$a0
}