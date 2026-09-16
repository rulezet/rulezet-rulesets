rule Win_Trojan_Rch_2
{
strings:
	$a0 = { 0be4133f8b288be908f6be1c0d8bfffb0e3b2f3b3c3ae4b805008af61f39c023c98adb3bfd8ac02be8b97b022b292b }


condition:
	$a0
}