rule Win_Trojan_Zamol_4
{
strings:
	$a0 = { 830e13090190f9c332c090cf9c2eff1eee0890fac39c5790bf0c092ea0be08900caa2e300547 }


condition:
	$a0
}