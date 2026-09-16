rule Win_Trojan_Tempest_2
{
strings:
	$a0 = { 687474703a2f2f737a656c7665737a2e32752e73652f68756e }


condition:
	$a0
}