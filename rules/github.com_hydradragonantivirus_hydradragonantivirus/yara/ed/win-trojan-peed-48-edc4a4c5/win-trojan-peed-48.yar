rule Win_Trojan_Peed_48
{
strings:
	$a0 = { 89c189e58b6d1c83ed054885ed75f8bf33c97333 }


condition:
	$a0
}