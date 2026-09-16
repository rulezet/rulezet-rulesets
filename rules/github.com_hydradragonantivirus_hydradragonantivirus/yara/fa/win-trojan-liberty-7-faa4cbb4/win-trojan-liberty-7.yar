rule Win_Trojan_Liberty_7
{
strings:
	$a0 = { 21fa0e1fb425a02e01baffff1f1ecd2107060e1fbf00 }


condition:
	$a0
}