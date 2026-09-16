rule Win_Trojan_Hexzone_2
{
strings:
	$a0 = { 5cbac400fe00080a012e4dcd54000005011117007900670074006c00690062002e0064006c006c }


condition:
	$a0
}