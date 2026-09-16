rule Win_Trojan_Vobfus_45
{
strings:
	$a0 = { 71717a78797870620000000000005000 }


condition:
	$a0
}