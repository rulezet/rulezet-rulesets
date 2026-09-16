rule Win_Trojan_Rosen_1
{
strings:
	$a0 = { 0657cb1e07be8301bf00011e57b9fffe2bcef3a4cb }


condition:
	$a0
}