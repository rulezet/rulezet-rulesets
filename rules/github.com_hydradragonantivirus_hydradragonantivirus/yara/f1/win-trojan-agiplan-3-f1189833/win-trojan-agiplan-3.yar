rule Win_Trojan_Agiplan_3
{
strings:
	$a0 = { eeba7100ec3cf07603e99a00b87f35cd }


condition:
	$a0
}