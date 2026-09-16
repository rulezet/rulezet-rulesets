rule Win_Trojan_B_108
{
strings:
	$a0 = { 03b80203bb0002b109880e3a01cd137214bebe05bfbe01b121fcf3a5b8010333dbb101cd13 }


condition:
	$a0
}