rule Win_Trojan_Gen_111
{
strings:
	$a0 = { 014383e1feba380303d6cd21b8023dba }


condition:
	$a0
}