rule Win_Trojan_Rbot_60
{
strings:
	$a0 = { 558bec6aff686820400068e017400064a10000000050648925 }


condition:
	$a0
}