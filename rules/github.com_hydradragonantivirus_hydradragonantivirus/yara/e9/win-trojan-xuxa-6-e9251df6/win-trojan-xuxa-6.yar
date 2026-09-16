rule Win_Trojan_Xuxa_6
{
strings:
	$a0 = { 083e80be5b060074268db63d00b93b062e8b9637002e8b0433c2fec22e890446b412cd16e2ef }


condition:
	$a0
}