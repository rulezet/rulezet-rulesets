rule Win_Trojan_SlowDown_1
{
strings:
	$a0 = { 509ac6027c00b802009ad800ea009aaa0eea003d01007e23bf9c021e57bf1d020e5731c050 }


condition:
	$a0
}