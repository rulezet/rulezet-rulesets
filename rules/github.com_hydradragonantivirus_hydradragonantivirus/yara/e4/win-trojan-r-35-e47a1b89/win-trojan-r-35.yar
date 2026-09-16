rule Win_Trojan_R_35
{
strings:
	$a0 = { b440b935028d960401cd21e80100c38b8621018db64701b9f90031044646e2fac3 }


condition:
	$a0
}