rule Win_Trojan_Kernel_1
{
strings:
	$a0 = { 80fc4b74039debee5053510656571e52b404cd1a81fa08 }


condition:
	$a0
}