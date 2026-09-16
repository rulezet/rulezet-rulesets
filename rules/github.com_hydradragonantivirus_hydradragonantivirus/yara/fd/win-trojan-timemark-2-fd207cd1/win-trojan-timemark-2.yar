rule Win_Trojan_Timemark_2
{
strings:
	$a0 = { ee4bcd217203eb6f9007068cc34b8edb8b1e030083eb44 }


condition:
	$a0
}