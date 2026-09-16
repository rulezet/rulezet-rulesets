rule Win_Trojan_SillyRE_3
{
strings:
	$a0 = { 515256571e068cc88ed82e2b0682002ea3820033c08ed8803e1204997503eb5490b44abbffffcd2183eb21b44acd }


condition:
	$a0
}