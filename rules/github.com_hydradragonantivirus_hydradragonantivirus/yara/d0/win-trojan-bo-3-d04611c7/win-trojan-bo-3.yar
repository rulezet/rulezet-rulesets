rule Win_Trojan_Bo_3
{
strings:
	$a0 = { 558bec6aff683822400068c01d400064a1 }

	$a1 = { 4261636b204f7269666963652050696e676572 }


condition:
	$a0 and $a1
}