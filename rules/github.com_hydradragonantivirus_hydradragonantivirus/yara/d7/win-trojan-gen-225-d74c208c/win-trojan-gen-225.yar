rule Win_Trojan_Gen_225
{
strings:
	$a0 = { 040077f7015c012eb9eb9e04b9ee7eb0baea3c4f77017202b04fb4e80962fd6bf1e5c70e9ce208 }


condition:
	$a0
}