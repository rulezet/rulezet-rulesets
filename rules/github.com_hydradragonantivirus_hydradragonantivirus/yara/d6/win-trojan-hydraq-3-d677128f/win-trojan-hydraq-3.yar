rule Win_Trojan_Hydraq_3
{
strings:
	$a0 = { 5c635f313735382e6e6c73 }


condition:
	$a0
}