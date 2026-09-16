rule Win_Trojan_Trojan_79
{
strings:
	$a0 = { 595b58071f9c2eff1e3b001e07b449cd }


condition:
	$a0
}