rule Win_Trojan_Benny_3
{
strings:
	$a0 = { 248bee81ed061040008dbddf174000ac84c0740c3cff0f847c0000003c0f7203aaebec568db5 }


condition:
	$a0
}