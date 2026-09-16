rule Win_Trojan_TheEraser_1
{
strings:
	$a0 = { 8f8eea95e78ac3cfc7c0eaa7e787dae6ebcbfceffdebfcea9495 }


condition:
	$a0
}