rule Win_Trojan_Y_18
{
strings:
	$a0 = { 120446ff0cadc1e0068ec0bb007c8bf3e81b00be4c00a5a5c744fca2008944fe06b86b0050 }


condition:
	$a0
}