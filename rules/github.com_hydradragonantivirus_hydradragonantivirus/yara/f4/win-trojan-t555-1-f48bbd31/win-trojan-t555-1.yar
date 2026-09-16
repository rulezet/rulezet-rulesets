rule Win_Trojan_T555_1
{
strings:
	$a0 = { 68e544474140591efb46471375ab85b092c6baf23241b092 }


condition:
	$a0
}