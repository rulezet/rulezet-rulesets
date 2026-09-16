rule Win_Trojan_Kode_3
{
strings:
	$a0 = { 568b7401bfac0103fe8b058a4d02bf00018905884d02b44ebaa30103d6cd217302eb6ab8023dba9e00cd2173 }


condition:
	$a0
}