rule Win_Trojan_Beavis_2
{
strings:
	$a0 = { 44bb5c7cbe04018a0734904e30000bf675f9c3149a00f0007c }


condition:
	$a0
}