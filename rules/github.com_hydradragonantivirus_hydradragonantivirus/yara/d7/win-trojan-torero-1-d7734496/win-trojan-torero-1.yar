rule Win_Trojan_Torero_1
{
strings:
	$a0 = { 773d50e81c01b440b99305ba0000e84700582d0300 }


condition:
	$a0
}