rule Win_Trojan_HH_2
{
strings:
	$a0 = { 40b900048306c80201cd21803ed80200740c32c0e8 }


condition:
	$a0
}