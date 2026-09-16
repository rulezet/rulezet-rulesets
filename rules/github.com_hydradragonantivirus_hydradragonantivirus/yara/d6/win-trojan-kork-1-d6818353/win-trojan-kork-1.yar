rule Win_Trojan_Kork_1
{
strings:
	$a0 = { 4a018cca03d08cc981c1dc0151b90100510606b1ff518cd383eb1853b13efc518cd5be420033ff4d8ec58eda4ab108 }


condition:
	$a0
}