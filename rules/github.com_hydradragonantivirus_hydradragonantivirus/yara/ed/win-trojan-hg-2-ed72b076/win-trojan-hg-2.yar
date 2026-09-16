rule Win_Trojan_HG_2
{
strings:
	$a0 = { 57cd21890ebf008916c100b40980c437b9b8019033d2cd2db40980c437b90a008d16d001cd2d }


condition:
	$a0
}