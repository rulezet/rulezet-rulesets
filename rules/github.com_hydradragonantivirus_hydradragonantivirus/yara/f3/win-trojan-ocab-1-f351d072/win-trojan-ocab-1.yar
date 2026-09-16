rule Win_Trojan_Ocab_1
{
strings:
	$a0 = { 4801cd217229b8023dba9e00cd2193b80057cd215152b440b9bd01ba0001cd21b801575a59cd21 }


condition:
	$a0
}