rule Win_Trojan_Trojan_169
{
strings:
	$a0 = { 59eb005e5dc3558beca10403051e008bd033c9b001b443cd }


condition:
	$a0
}