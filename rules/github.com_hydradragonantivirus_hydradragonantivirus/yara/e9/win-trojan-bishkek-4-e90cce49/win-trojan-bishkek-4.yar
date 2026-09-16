rule Win_Trojan_Bishkek_4
{
strings:
	$a0 = { 740f3d084261050a3d0d05053d01b0d00e0220bf754f0005604821fbb409ba0200cd8a }


condition:
	$a0
}