rule Win_Trojan_Miss_1
{
strings:
	$a0 = { ac01bf5006e88b01b82135cd212e891e18042e8c061a04b877efcd2180fc0074102ec606290301 }


condition:
	$a0
}