rule Win_Spyware_ye_154
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]9765a176b2d184365805a812b2d78f }


condition:
	$a0
}