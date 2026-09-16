rule Win_Trojan_SST_4
{
strings:
	$a0 = { 02b92902ba0001cd21befa0103f58b0c80e1e080c1078b5402b80157cd218a260003cd21a1 }


condition:
	$a0
}