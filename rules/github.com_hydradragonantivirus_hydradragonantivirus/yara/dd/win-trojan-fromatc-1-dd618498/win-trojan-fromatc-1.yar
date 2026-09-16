rule Win_Trojan_FromatC_1
{
strings:
	$a0 = { 404543484f204f4646[1-200]464f524d415420433a[1-5]2f51 }


condition:
	$a0
}