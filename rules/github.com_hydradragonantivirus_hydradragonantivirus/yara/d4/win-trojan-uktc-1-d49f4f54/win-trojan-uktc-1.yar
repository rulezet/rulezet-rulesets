rule Win_Trojan_UKTC_1
{
strings:
	$a0 = { 5e0350be2d018bfeba0004ac32060004aa3bf275f6c3 }


condition:
	$a0
}