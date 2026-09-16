rule Win_Trojan_Onlinegames_25
{
strings:
	$a0 = { 558bec81c4c4feffffe802001b1be8020007350bc07505e9 }

	$a1 = { 53656c6644656c2e626174 }


condition:
	$a0 and $a1
}