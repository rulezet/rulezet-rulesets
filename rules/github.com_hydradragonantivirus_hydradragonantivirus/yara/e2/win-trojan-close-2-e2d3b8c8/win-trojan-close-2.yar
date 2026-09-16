rule Win_Trojan_Close_2
{
strings:
	$a0 = { ff0f5b868383869383d33b8383d3b0430f590d5b02bd9386139a8e8e0d59487900ad9087810841cb0d5b3b0383aa }


condition:
	$a0
}