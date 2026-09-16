rule Win_Trojan_VB_1027
{
strings:
	$a0 = { 6838124000e8f0ffffff0000000000003000000038 }

	$a1 = { 54726f6a616e }

	$a2 = { 4261636b446f6f72 }

	$a3 = { 466f746f }

	$a4 = { 537079 }

	$a5 = { 56696374696d73496e666f }


condition:
	$a0 and $a1 and $a2 and $a3 and $a4 and $a5
}