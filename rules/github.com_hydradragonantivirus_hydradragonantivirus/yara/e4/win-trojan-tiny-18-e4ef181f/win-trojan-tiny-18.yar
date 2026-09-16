rule Win_Trojan_Tiny_18
{
strings:
	$a0 = { 06570e59f3a4ba4601b44ecd217301cbb8023dba9e00cd2193b43fba4b018bcccd21054b00 }


condition:
	$a0
}