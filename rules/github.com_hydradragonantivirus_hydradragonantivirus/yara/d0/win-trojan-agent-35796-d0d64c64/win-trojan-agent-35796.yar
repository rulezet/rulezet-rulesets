rule Win_Trojan_Agent_35796
{
strings:
	$a0 = { 558bec6aff68f060400068a053400064a100000000506489250000000083ec68 }


condition:
	$a0
}