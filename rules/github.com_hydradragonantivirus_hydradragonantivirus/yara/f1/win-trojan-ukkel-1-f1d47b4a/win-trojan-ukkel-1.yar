rule Win_Trojan_Ukkel_1
{
strings:
	$a0 = { e80000bf40008edf836dd3068b45d3b10ad3c88ec0b8090233dbb90800ba8000cd1372030653cb }


condition:
	$a0
}