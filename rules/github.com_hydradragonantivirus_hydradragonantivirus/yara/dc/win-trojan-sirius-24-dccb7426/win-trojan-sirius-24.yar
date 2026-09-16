rule Win_Trojan_Sirius_24
{
strings:
	$a0 = { e80000582d0801958db62401568b963202b987008bfead33c2d1caabe2f8c3 }


condition:
	$a0
}