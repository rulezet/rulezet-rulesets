rule Win_Trojan_Look_3
{
strings:
	$a0 = { 8150ff7606e8fe2559598bf883ffff7438b80040508d86febf5056e88b2b83c4068946feff76 }


condition:
	$a0
}