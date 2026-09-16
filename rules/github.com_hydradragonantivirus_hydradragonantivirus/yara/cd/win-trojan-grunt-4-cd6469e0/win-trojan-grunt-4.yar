rule Win_Trojan_Grunt_4
{
strings:
	$a0 = { e2fe3e8b9655028d9e2901b97700311783c302e2f9c3e800005d81ed2101e8dcffd937695c604e7c4f1f2a }


condition:
	$a0
}