rule Win_Trojan_V_13
{
strings:
	$a0 = { 8a05d0c088054739d775f5bf2201e8fe028b05bff0 }


condition:
	$a0
}