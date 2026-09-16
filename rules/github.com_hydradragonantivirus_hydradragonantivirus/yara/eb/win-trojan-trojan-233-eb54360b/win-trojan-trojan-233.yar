rule Win_Trojan_Trojan_233
{
strings:
	$a0 = { 75f77be730c112eec8e4320c6a45d90eff2cd0f61f153287da0a8a2c07c113b4fd9c148b35c1122ab50b }


condition:
	$a0
}