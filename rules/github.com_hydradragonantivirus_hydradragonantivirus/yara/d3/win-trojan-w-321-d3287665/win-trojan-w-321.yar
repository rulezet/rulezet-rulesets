rule Win_Trojan_W_321
{
strings:
	$a0 = { 570f014c24fe5fdf2f500417abab58ff77028f47facd00df7ff8c705c112 }


condition:
	$a0
}