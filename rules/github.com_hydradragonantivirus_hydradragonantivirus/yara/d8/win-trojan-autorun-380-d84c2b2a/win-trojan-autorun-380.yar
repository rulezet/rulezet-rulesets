rule Win_Trojan_Autorun_380
{
strings:
	$a0 = { 6f70656e3d777363726970742e657865202f2f653a7662736372697074 }

	$a1 = { 6175746f }


condition:
	$a0 and $a1
}