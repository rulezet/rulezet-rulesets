rule Win_Trojan_Stimp_1
{
strings:
	$a0 = { 16f601bb0501b958009031179083c30290e2f6c3 }


condition:
	$a0
}