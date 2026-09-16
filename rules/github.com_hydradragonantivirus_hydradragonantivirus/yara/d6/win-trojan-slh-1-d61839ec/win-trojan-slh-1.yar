rule Win_Trojan_SLH_1
{
strings:
	$a0 = { 018b963802b97e003117eb0783c302e2f75bc3ebf7472b }


condition:
	$a0
}