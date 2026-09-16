rule Win_Trojan_Vanish_1
{
strings:
	$a0 = { ccb26a504823c00bc040583014504823c00bc04058461617cce2db }


condition:
	$a0
}