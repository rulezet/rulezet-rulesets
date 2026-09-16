rule Win_Trojan_Peed_284
{
strings:
	$a0 = { e89800000068c07600005981c1005f000081c1c0760000baff89bffff7d289d652ac86c4 }


condition:
	$a0
}