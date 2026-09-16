rule Win_Trojan_Grog_4
{
strings:
	$a0 = { 894ffb8b0e160103c8894ff78b0e1001894ff98b }


condition:
	$a0
}