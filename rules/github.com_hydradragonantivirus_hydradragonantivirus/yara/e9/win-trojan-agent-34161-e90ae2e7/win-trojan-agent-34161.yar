rule Win_Trojan_Agent_34161
{
strings:
	$a0 = { c78424??ffff }

	$a1 = { 81c46cfdffff }


condition:
	$a0 and $a1
}