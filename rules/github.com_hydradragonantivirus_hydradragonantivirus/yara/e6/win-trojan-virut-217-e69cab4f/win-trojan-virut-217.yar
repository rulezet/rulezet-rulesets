rule Win_Trojan_Virut_217
{
strings:
	$a0 = { fce82900000053b9ce0d00008bda6631104086d6408d1413e2f45bc3 }


condition:
	$a0
}