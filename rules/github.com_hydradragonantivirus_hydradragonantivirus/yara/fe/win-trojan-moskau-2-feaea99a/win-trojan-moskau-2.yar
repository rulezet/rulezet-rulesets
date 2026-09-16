rule Win_Trojan_Moskau_2
{
strings:
	$a0 = { 8bf581c659018cc8cd013ec686c400568bc505c602ffe0 }


condition:
	$a0
}