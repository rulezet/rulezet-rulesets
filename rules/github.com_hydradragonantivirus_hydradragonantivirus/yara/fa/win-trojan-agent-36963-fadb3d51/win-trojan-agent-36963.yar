rule Win_Trojan_Agent_36963
{
strings:
	$a0 = { 3a454c31355f7365645f6b69737365735f746f5f555f3a295f5f636f6d655f6f6e21 }


condition:
	$a0
}