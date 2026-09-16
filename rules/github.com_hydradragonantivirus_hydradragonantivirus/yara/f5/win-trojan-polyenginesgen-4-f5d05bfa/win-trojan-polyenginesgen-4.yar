rule Win_Trojan_PolyEngineSGen_4
{
strings:
	$a0 = { 5601cd21b9320051b43c33c9ba6801cd2193b8d107b104d3e88cc903c18ec053bb0001b92600ba7301e8db005b }


condition:
	$a0
}