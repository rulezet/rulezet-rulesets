rule Win_Trojan_Joker_1
{
strings:
	$a0 = { 9a0000db009a0000750089e581ec0001bf00000e57bf6e1a1e57b80c00509ada02db0031c0a3431abf0d000e57bf2b00 }


condition:
	$a0
}