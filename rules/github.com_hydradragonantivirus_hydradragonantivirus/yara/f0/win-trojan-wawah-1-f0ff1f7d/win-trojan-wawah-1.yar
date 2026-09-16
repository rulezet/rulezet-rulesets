rule Win_Trojan_Wawah_1
{
strings:
	$a0 = { 10e003c7441449015958b440b91303ba00019c2eff1e1a01721db8004233c933d29c2eff1e1a }


condition:
	$a0
}