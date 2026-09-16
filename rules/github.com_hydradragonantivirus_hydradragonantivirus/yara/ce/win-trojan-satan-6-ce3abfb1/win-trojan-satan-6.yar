rule Win_Trojan_Satan_6
{
strings:
	$a0 = { 01b42acd2180fe0c750880fa197503e9db0180fe04750880fa017503e9d001e8ab01e895018b }


condition:
	$a0
}