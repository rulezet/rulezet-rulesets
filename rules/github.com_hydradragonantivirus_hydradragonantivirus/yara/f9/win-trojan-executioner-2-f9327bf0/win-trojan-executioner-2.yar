rule Win_Trojan_Executioner_2
{
strings:
	$a0 = { e800008bec8b6e0081ed050083c402b8ff42cd2181fbd20474778cd8488ed8c60600005a812e }


condition:
	$a0
}