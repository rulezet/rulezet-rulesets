rule Win_Trojan_LG_3
{
strings:
	$a0 = { 03dd0e1f3e89ae8e0050cd255a5872188b97fe0181fa55aa740eb90200cd255a81bf60034c }


condition:
	$a0
}