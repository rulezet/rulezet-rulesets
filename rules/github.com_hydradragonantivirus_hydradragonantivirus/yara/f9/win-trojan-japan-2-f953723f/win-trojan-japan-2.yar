rule Win_Trojan_Japan_2
{
strings:
	$a0 = { 040481c18d028bd581c20005cd21 }


condition:
	$a0
}