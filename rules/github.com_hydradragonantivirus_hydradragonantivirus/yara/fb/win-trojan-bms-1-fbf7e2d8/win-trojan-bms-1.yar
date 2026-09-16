rule Win_Trojan_BMS_1
{
strings:
	$a0 = { 51e89000bebc03e86d028b4cfe83e10383c1038344fe0451e8f700593c007502e2f5b41a8e5c028b14cd211f07817c }


condition:
	$a0
}