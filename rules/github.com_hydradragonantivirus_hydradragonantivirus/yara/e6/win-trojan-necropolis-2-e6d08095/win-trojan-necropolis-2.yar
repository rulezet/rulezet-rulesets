rule Win_Trojan_Necropolis_2
{
strings:
	$a0 = { cd213c037207b80012cd2f3cffb80b007271b44abb4001cd217268fa0e17bcfe13e8c500fba12c000bc07461e8bb068ec033ff33c0af75fdaf8bd7061fb4 }


condition:
	$a0
}