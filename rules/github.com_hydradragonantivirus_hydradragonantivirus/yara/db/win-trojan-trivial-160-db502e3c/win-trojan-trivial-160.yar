rule Win_Trojan_Trivial_160
{
strings:
	$a0 = { b120ba1b01cd21b8013dba9e00cd218bd8b440ba0001cd21c3 }


condition:
	$a0
}