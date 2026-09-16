rule Win_Trojan_Yaunch_3
{
strings:
	$a0 = { 16a6012e8926a8010e17bca601fb505351521e060e1fbf0000ba5c01e8f607bfde01bac209 }


condition:
	$a0
}