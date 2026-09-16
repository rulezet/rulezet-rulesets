rule Win_Spyware_ye_64
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]3d83479c587f2a5c06abd6c0e0853d }


condition:
	$a0
}