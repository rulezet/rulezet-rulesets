rule Win_Trojan_Duwende_10
{
strings:
	$a0 = { 3fba7500b103cd215a8b441a2bc12bc28944015a59585051cd218bd6b103b440cd2159588b541a }


condition:
	$a0
}