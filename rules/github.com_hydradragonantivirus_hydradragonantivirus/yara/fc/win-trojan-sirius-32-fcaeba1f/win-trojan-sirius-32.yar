rule Win_Trojan_Sirius_32
{
strings:
	$a0 = { e80000582d0801958db62401568b96df03b95d018bfead33c2d1caabe2f8c3 }


condition:
	$a0
}