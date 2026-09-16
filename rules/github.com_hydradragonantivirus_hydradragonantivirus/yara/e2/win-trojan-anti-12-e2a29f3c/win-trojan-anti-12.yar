rule Win_Trojan_Anti_12
{
strings:
	$a0 = { 4c002e8984bdfd2e8c84bffdc41e8400 }


condition:
	$a0
}