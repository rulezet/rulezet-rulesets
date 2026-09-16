rule Win_Trojan_Gly_1
{
strings:
	$a0 = { 4f74493daaaa75049df7d0cf9d2eff2e7e049c2eff1e }


condition:
	$a0
}