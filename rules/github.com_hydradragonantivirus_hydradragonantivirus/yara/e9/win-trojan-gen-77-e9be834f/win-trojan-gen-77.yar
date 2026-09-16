rule Win_Trojan_Gen_77
{
strings:
	$a0 = { 6001cd21bf5201a12c008ed80e07ab }


condition:
	$a0
}