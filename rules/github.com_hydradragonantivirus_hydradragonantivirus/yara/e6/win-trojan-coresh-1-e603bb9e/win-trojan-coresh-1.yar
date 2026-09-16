rule Win_Trojan_Coresh_1
{
strings:
	$a0 = { 56344d474e785a576c76636d686a4f4739795a51 }


condition:
	$a0
}