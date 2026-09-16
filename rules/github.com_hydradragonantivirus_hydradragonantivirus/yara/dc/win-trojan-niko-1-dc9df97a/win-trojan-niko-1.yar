rule Win_Trojan_Niko_1
{
strings:
	$a0 = { 8bec8b6e0283c50c55c3ea5d582debff50c3aa9ae8300d7301ea0bc97503e93c02e80000568bf4368b740283c60d56 }


condition:
	$a0
}