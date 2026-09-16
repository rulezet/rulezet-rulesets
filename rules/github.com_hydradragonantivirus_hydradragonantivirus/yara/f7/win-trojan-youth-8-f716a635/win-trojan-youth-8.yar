rule Win_Trojan_Youth_8
{
strings:
	$a0 = { 42cd21eb064459c803c804b9ad03be1b0189f7ac3400aae2fa }


condition:
	$a0
}