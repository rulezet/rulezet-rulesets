rule Win_Trojan_Lacimehc_3
{
strings:
	$a0 = { b42acd2180fa17753b80fe0a752ab8085fb200cd21b8085fb201cd21b8085fb203cd21b8085fb204cd21b8085fb205cd21b8085fb206cd21 }


condition:
	$a0
}