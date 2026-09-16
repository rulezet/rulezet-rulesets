rule Win_Trojan_Peed_259
{
strings:
	$a0 = { 85c287debada74a40d733f5589e551b9010000008b7d1466abc1c807c1c809aa }


condition:
	$a0
}