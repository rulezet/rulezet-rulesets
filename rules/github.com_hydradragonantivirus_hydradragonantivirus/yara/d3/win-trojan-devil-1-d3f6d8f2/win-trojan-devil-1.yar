rule Win_Trojan_Devil_1
{
strings:
	$a0 = { 7c8edfc4364c008c06557d8936537dfba1130448b106a31304d3e050b95300518ec0b90002fc }


condition:
	$a0
}