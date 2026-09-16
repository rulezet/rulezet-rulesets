rule Win_Spyware_ye_155
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]9866a277b3d285375906a913b3d080 }


condition:
	$a0
}