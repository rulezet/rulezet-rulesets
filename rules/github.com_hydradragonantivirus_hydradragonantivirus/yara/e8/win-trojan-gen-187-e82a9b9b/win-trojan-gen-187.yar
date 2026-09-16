rule Win_Trojan_Gen_187
{
strings:
	$a0 = { 7900f72698ef8bf88a85cb0230e448509af506da00b87900f72698ef8bf881c7cb021e57b87800 }


condition:
	$a0
}