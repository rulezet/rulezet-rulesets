rule Win_Trojan_Gen_228
{
strings:
	$a0 = { f73b6d000d760dc72bc67404434a75100adec3803e4c151b66c1a098e010660facd005c1e18a02 }


condition:
	$a0
}