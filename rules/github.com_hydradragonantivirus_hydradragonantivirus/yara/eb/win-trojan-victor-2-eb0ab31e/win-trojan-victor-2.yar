rule Win_Trojan_Victor_2
{
strings:
	$a0 = { f308b42ccd2189167200b42ccd218aca80e10fd3067200 }


condition:
	$a0
}