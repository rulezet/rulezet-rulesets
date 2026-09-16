rule Win_Trojan_Kaszana_2
{
strings:
	$a0 = { 30098ce23642fe4140eceaedeb1fccd5c742f55b8c6047f965748c60c81d1ecd052046cc1522f564 }


condition:
	$a0
}