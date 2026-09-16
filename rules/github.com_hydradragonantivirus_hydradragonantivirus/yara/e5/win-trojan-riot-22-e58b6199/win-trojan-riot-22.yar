rule Win_Trojan_Riot_22
{
strings:
	$a0 = { 620732c0e87f00b4408d967f03b90300cd2148e870008db603018dbe720457b97701f3a55f8b }


condition:
	$a0
}