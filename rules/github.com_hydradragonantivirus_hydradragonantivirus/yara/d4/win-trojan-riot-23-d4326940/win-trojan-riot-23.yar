rule Win_Trojan_Riot_23
{
strings:
	$a0 = { 0732c0e87f00b4408d967803b90300cd2148e870008db603018dbe6b0457b97401f3a55f8b }


condition:
	$a0
}