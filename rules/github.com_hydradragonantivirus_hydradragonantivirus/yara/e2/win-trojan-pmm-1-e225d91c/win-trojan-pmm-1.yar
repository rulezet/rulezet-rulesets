rule Win_Trojan_PMM_1
{
strings:
	$a0 = { e800005f81c754011fac3c70736c3c4073f7a8c4740924 }


condition:
	$a0
}