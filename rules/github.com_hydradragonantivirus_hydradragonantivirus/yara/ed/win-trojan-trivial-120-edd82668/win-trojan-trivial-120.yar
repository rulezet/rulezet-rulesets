rule Win_Trojan_Trivial_120
{
strings:
	$a0 = { 1801b44ecd21ba9e00b43ccd21ba0001b740b11c93cd21 }


condition:
	$a0
}