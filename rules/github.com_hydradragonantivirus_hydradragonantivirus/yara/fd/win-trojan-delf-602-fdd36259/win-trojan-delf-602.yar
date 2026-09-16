rule Win_Trojan_Delf_602
{
strings:
	$a0 = { 2b00000061393d494d502d4b65796c6f676765722034 }


condition:
	$a0
}