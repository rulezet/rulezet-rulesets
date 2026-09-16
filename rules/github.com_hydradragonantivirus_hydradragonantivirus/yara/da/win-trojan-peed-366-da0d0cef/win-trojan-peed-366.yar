rule Win_Trojan_Peed_366
{
strings:
	$a0 = { 81c79900000081ff99000000744c81ff0fc00000 }


condition:
	$a0
}