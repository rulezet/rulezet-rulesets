rule Win_Trojan_Mono_17
{
strings:
	$a0 = { 8bc98bc98bc9908bc98bd2908bdb8bd2908bc9908bd28bc9908bc9908bc98bc990908bd28bd28bc9908bc98bc98bc990 }


condition:
	$a0
}