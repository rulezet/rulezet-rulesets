rule Win_Trojan_Dos7_2
{
strings:
	$a0 = { 72163b060001740d8b44023d1560740deb4aeb5e90b4 }


condition:
	$a0
}