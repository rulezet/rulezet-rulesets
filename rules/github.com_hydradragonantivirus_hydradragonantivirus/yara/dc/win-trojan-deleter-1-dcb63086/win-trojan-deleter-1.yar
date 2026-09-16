rule Win_Trojan_Deleter_1
{
strings:
	$a0 = { 8b005589e58b5e0483c30fb104d3eb035e06a1f60029c38ec0b44acd21eb0b5b44656c657465722d355d }


condition:
	$a0
}