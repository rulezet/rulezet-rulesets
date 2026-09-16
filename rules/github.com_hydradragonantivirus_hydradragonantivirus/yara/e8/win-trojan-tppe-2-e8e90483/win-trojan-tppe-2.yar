rule Win_Trojan_TPPE_2
{
strings:
	$a0 = { bf35100e57bf600c1e57b8ff00509aa70b410189ec5dc32c5468697320697320484c4c4f2e }


condition:
	$a0
}