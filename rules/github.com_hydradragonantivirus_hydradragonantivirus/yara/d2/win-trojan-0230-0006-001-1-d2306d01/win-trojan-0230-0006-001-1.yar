rule Win_Trojan__0230_0006_001_1
{
strings:
	$a0 = { e003b440b90300baf3030e1f9c2eff1ee003b801572e8b0eef0380e1e080c90d2e8b16f1039c }


condition:
	$a0
}