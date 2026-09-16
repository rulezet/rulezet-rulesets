rule Win_Trojan_Small_4469
{
strings:
	$a0 = { 8b44241c8d8032cb8303506832554303e8540000004050ba62b8ec0e52505155 }


condition:
	$a0
}