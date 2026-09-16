rule Win_Trojan_VGEN_434
{
strings:
	$a0 = { 0d012e8a847b032e8c84980350061e0e0e071fffb47703ffb47903ffb47303ffb47503ffb47c03ffb47e038d94df03 }


condition:
	$a0
}