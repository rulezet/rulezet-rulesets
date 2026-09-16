rule Win_Trojan_Birgit_19
{
strings:
	$a0 = { e2fdbaf301ffd2c353badb01ffd25bb440b9f300ba0001cd2153badb01ffd25bc3 }


condition:
	$a0
}