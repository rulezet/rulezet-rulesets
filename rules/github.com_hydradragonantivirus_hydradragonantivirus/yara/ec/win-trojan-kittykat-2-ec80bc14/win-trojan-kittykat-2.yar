rule Win_Trojan_Kittykat_2
{
strings:
	$a0 = { 6a04680010000068000001006a00ff1591304000a300104000684410 }


condition:
	$a0
}