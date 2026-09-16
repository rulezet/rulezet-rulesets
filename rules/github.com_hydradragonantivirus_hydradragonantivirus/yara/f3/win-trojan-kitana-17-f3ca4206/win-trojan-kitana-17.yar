rule Win_Trojan_Kitana_17
{
strings:
	$a0 = { 8bd8cd138b073d85d2741433c048cd1385c0740bb8010341cd134987f3cd13c387de2eff0e1304 }


condition:
	$a0
}