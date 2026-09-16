rule Win_Trojan_Sebek_1
{
strings:
	$a0 = { cd213dbaab742eb430cd213c037226c70680011027b80000068ec026a12000a37c0126a12200a37e01078306a7 }


condition:
	$a0
}