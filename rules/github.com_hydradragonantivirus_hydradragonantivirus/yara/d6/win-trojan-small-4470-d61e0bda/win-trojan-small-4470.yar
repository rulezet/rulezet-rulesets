rule Win_Trojan_Small_4470
{
strings:
	$a0 = { 8b44241c8d80????8303506832554303e8540000004050ba????ec0e52505155 }


condition:
	$a0
}