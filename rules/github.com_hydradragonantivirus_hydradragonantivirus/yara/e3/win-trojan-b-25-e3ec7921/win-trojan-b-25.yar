rule Win_Trojan_B_25
{
strings:
	$a0 = { b089c0cd2feb000e1fc606e80a00e8d800b80012cd2ffec07508 }


condition:
	$a0
}