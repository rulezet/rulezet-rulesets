rule Win_Trojan_Skintrim_31
{
strings:
	$a0 = { 558bec6aff68d8164400683066430064a10000000050648925 }

	$a1 = { 466c756973204b4742 }

	$a2 = { 3123514e414e00003123494e46 }


condition:
	$a0 and $a1 and $a2
}