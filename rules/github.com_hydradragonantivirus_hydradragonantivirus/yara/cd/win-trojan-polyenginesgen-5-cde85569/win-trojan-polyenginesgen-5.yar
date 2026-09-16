rule Win_Trojan_PolyEngineSGen_5
{
strings:
	$a0 = { 6201cd21b8cd08b104d3e88ccb03d88ec3b9320051b43c33c9ba5501cd2193bd0001b91f00ba870153b302e888 }


condition:
	$a0
}