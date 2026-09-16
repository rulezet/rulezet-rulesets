rule Win_Trojan_Pizza_1
{
strings:
	$a0 = { 9069909090cd2090e800005d81ed0d0150e80200eb208a8637078db63501b900063004d2c046e2f9c3 }


condition:
	$a0
}