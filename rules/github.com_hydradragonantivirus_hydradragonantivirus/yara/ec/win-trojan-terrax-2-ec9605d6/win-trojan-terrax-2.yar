rule Win_Trojan_TerraX_2
{
strings:
	$a0 = { 8c9c0a008c9c0e008c9c1200b404cd1a80fa187538525ae54025030303d0e5402503032bd05280fe1277eb80fa }


condition:
	$a0
}