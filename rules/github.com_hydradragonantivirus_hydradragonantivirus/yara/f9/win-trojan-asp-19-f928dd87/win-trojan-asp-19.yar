rule Win_Trojan_ASP_19
{
strings:
	$a0 = { 2e6f70656e2022676574222c2074686575726c }

	$a1 = { 696e6465782e68746d2e747874 }


condition:
	$a0 and $a1
}