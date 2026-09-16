rule Win_Trojan_B_2
{
strings:
	$a0 = { 1233c0cd1333c08ec0b80102bb007c2e803e050000740ab90700ba8000cd13 }


condition:
	$a0
}