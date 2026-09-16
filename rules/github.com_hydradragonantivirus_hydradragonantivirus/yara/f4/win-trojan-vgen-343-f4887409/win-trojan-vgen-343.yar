rule Win_Trojan_VGEN_343
{
strings:
	$a0 = { e303cd21baf603b90200b44ecd21b44fbaf603cd21b8023dba9e00cd2193b91103b440ba0001cd21b43ecd21ff }


condition:
	$a0
}