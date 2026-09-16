rule Win_Trojan_Zlo_1
{
strings:
	$a0 = { e80000582d0400408be88bf581c6????bf0001fca5a5e8????51e8????8bdd81c3 }


condition:
	$a0
}