rule Win_Trojan_Sabotager_1
{
strings:
	$a0 = { bd2d881de505b743b9a302ba07039f2dfc1de10571aa2d881de505bb014130ca30d19f2dfc1de105 }


condition:
	$a0
}