rule Win_Trojan_Atas_1
{
strings:
	$a0 = { 8b2e0201b009b9df04be150001ee3004fec846e2f9 }


condition:
	$a0
}