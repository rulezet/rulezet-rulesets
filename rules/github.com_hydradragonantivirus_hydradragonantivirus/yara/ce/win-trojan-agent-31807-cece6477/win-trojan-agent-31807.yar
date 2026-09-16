rule Win_Trojan_Agent_31807
{
strings:
	$a0 = { 6a0140508d4c240c516824f300106810f700106802000080e8d60c0000 }


condition:
	$a0
}