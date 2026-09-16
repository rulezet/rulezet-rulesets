rule Win_Trojan_Aman_1
{
strings:
	$a0 = { fc8bc1501f2e8c06003a2ea1cf292ea363002ea1d1292ea36500b42fcd212e8c06023a2e891e043a1e07e8a5003d }


condition:
	$a0
}