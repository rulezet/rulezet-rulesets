rule Win_Trojan_Dowcipas_2
{
strings:
	$a0 = { 0103cd13720d8b56128e5e10b80043cd217303e909ff5133c9b80143cd215972f251b8823dcd21 }


condition:
	$a0
}