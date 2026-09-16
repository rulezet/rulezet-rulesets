rule Win_Trojan_Oxana_5
{
strings:
	$a0 = { 056c019a12b700b4028a169d078a369e07cd10b409b90100b0dacd108a169d07fec2b4028a369e07cd10b409b901 }


condition:
	$a0
}