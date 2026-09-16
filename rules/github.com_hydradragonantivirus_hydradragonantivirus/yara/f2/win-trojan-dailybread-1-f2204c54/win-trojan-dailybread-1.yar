rule Win_Trojan_DailyBread_1
{
strings:
	$a0 = { fee82afd730de841fd7308e8aefd7303e823fee8acfe58fa2e8e1654032e8b265603fb2eff }


condition:
	$a0
}