rule Win_Trojan_Agent_34350
{
strings:
	$a0 = { 83c8d66083d8e4e8a801000072aa60f539710000b6f883eca40d5bb82eb60100 }


condition:
	$a0
}