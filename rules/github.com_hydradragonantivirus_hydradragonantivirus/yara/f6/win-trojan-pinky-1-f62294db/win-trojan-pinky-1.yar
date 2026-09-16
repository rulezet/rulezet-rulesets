rule Win_Trojan_Pinky_1
{
strings:
	$a0 = { 0701b95803be0a018bfefcac02c4aae2fac38a260701 }


condition:
	$a0
}