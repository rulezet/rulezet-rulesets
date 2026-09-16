rule Win_Trojan_Plunix_1
{
strings:
	$a0 = { 6a196804e700108d8c2438010000e83bf6ffff6a38c784246805000000000000e8fb750000 }


condition:
	$a0
}