rule Win_Trojan_AAEH_9
{
strings:
	$a0 = { 2d433030302d78706179 }

	$a1 = { 3f287b10fac973cb7ecb720ad16a7d13ccec39cf61789e96063beb66c491c06f8e1c2e81cd8372d6ea38ab766d5c4fe2 }


condition:
	$a0 and $a1
}