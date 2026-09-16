rule Win_Trojan_Peed_309
{
strings:
	$a0 = { 89e554e84e000000ab50525183c8ff40059d }


condition:
	$a0
}