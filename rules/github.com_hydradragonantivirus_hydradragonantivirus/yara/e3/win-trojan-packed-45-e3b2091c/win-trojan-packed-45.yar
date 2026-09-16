rule Win_Trojan_Packed_45
{
strings:
	$a0 = { 90665066536658665b66[0-150]f6d0f6d01e16171f665066536658665b }


condition:
	$a0
}