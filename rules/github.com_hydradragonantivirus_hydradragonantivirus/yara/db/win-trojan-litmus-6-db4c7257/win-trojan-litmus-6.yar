rule Win_Trojan_Litmus_6
{
strings:
	$a0 = { 4c69746d757320322e303300f5fbeffbfafedbdad60d200d002020202020202020202020202e00 }


condition:
	$a0
}