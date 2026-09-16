rule Win_Trojan_Trivial_51
{
strings:
	$a0 = { 33c9ba6601cd217226b8013dba9e00cd2193b44050b91200ba0001cd2158b95a00ba7601cd21 }


condition:
	$a0
}