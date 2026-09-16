rule Win_Trojan_T4_1
{
strings:
	$a0 = { d1e9be63008bfead33c5abe2fa0bd274029dc3b440b95a0833d29cff1e5e089c42ebda }


condition:
	$a0
}