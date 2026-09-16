rule Win_Trojan_Nutz_1
{
strings:
	$a0 = { 485a585be84e0005280383d200b10950d3e8d3caf9 }


condition:
	$a0
}