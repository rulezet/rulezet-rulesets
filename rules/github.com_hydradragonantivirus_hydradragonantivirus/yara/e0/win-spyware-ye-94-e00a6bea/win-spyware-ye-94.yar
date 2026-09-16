rule Win_Spyware_ye_94
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]5ba165b2761d48721c416c5e06a3d3 }


condition:
	$a0
}