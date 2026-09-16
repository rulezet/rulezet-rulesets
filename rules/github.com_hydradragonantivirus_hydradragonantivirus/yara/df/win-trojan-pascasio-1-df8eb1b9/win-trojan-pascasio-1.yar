rule Win_Trojan_Pascasio_1
{
strings:
	$a0 = { ff00509a71095401bf84001e57bf84011e57e80ffe5dc32f20202020202020576169742033206d }


condition:
	$a0
}