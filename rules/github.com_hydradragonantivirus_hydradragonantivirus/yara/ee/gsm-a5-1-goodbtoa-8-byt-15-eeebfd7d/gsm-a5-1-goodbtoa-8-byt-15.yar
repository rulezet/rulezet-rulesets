rule GSM_A5_1_goodBtoA__8_byt_15_
{
strings:
	$a0 = { 24fd35a35d5fb6526d32f906df1ac0 }

condition:
	$a0
}