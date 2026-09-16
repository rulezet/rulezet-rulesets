rule Win_Trojan_K_12
{
strings:
	$a0 = { 01a087032ea20101a088032ea202018cc8a33603b980 }


condition:
	$a0
}