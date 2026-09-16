rule Win_Trojan_Agent_34413
{
strings:
	$a0 = { fce82800000053b9a20d00008bda6631104086d6408d1413e2f45bc363875dc3 }


condition:
	$a0
}