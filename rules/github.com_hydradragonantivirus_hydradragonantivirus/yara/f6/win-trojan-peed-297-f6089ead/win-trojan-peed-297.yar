rule Win_Trojan_Peed_297
{
strings:
	$a0 = { ba300cf9ff55e84700000068b6b200005981c17c47000081e96ec4ffff81e92ce8 }


condition:
	$a0
}