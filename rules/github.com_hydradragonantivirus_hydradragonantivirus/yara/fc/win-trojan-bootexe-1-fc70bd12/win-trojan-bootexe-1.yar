rule Win_Trojan_BootEXE_1
{
strings:
	$a0 = { ff0e1304cd12b90a01d3c88ec033ffbe417cfcf3a5e84501cd19b44abb2900cd2133f6ff742c }


condition:
	$a0
}