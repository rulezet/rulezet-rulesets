rule Win_Trojan_Vesna_7
{
strings:
	$a0 = { 0690bbd6072e8a3732f42e88374be2f5c340e8160660e8e3ff61ba00018a263e01b9d70690cd }


condition:
	$a0
}