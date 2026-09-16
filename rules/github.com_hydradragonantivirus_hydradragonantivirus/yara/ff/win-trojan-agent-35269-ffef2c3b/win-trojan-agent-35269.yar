rule Win_Trojan_Agent_35269
{
strings:
	$a0 = { 81c69865d04e5481ee9865d04e89342481c77836b0365481 }


condition:
	$a0
}