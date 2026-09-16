rule Win_Trojan_Jobi_1
{
strings:
	$a0 = { bb00028a161f009c2eff1e07007214b80103b90100b6008a161f0033db9c2eff1e07007208 }


condition:
	$a0
}