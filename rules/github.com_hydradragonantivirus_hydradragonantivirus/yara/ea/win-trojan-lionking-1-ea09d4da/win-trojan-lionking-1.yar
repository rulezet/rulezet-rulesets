rule Win_Trojan_LionKing_1
{
strings:
	$a0 = { b96e020e1f290e6c0b318f790bfc33cbf84b4b7df47e260be9f7f18bd8eda2077602ed9806b149c824ed2f0476 }


condition:
	$a0
}