rule Win_Trojan_Vinchuca_1
{
strings:
	$a0 = { 1d012e38057413f9be1d01720169b1032ed2044681fead0475f4177ca6b924307faee68e2d }


condition:
	$a0
}