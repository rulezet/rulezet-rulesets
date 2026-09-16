rule Win_Trojan_Uruguay_7
{
strings:
	$a0 = { 750b81fa34127505b878569dcfe954019cfb2ea397003d004b741c80fc3d7509a80775d9e8 }


condition:
	$a0
}