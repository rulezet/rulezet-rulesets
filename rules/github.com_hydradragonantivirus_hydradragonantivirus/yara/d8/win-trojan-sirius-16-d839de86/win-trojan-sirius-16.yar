rule Win_Trojan_Sirius_16
{
strings:
	$a0 = { b80bd922037fa4a26442af8d53b3e5ede4c3d4f7e0cdd29ae6f90a60d7 }


condition:
	$a0
}