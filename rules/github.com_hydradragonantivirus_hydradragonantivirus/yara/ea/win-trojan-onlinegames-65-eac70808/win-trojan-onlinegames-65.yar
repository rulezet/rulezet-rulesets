rule Win_Trojan_OnlineGames_65
{
strings:
	$a0 = { 4e657747616d65557064617465 }

	$a1 = { 47616d6556657273696f6e55706461746531 }

	$a2 = { 557064617465546f6f6c }


condition:
	$a0 and $a1 and $a2
}