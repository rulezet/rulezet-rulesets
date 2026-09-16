rule Win_Trojan_BHO_117
{
strings:
	$a0 = { 5253f8575056510f83beffffff4b2f8677f5fd }

	$a1 = { 5055540048454144[0-4]504f5354 }

	$a2 = { 696e7465726e65742e666e65 }


condition:
	$a0 and $a1 and $a2
}