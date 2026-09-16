rule Win_Trojan_Zbot_1240
{
strings:
	$a0 = { e809000000bf000000005ec20c0031f66a0068eed050006a146a0068682b1a006a1c6a }


condition:
	$a0
}