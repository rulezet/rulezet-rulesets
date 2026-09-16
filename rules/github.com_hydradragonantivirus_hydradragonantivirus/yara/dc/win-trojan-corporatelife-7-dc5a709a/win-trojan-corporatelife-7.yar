rule Win_Trojan_CorporateLife_7
{
strings:
	$a0 = { 90480efb1f48fbbd210790404848bf3e01fb40803519909048474090fb4d75f3fb904840484048409090fb409048 }


condition:
	$a0
}