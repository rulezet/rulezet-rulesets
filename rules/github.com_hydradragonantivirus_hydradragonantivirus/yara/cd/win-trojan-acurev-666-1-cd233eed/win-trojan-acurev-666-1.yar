rule Win_Trojan_Acurev_666_1
{
strings:
	$a0 = { 26018bfeb97402e80300eb0b90ac32062501aae2f8 }


condition:
	$a0
}