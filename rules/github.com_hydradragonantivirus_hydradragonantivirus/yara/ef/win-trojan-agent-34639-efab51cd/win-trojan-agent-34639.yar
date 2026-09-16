rule Win_Trojan_Agent_34639
{
strings:
	$a0 = { 4261636b444f4f4f522e657865 }

	$a1 = { 740065006d0070002e0062006d0070[0-111]4400610072006b004e }


condition:
	$a0 and $a1
}