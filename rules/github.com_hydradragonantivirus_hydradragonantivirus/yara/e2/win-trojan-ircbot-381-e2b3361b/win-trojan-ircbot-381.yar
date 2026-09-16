rule Win_Trojan_IRCBot_381
{
strings:
	$a0 = { 6c206c6f6c203a736861646f77626f74000000 }


condition:
	$a0
}