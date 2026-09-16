rule Win_Spyware_Banker_3061
{
strings:
	$a0 = { ab6d06533c4edbc82cb8368a9a61bbbd69a9256b9ae88083492f689db90caa345e785127c234b3fe4e01972c6dca908c612f5228a50a2d4deba5ec13ce96 }


condition:
	$a0
}