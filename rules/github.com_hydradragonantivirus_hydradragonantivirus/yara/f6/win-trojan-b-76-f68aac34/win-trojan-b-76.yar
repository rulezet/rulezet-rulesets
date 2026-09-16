rule Win_Trojan_B_76
{
strings:
	$a0 = { 733a3a34753680fc02740e80fc03752c80fa807227 }


condition:
	$a0
}