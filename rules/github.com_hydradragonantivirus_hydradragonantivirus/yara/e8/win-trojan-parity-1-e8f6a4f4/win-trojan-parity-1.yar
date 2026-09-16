rule Win_Trojan_Parity_1
{
strings:
	$a0 = { 0300b003cf06b82435cd212e899d7c02 }


condition:
	$a0
}