rule Win_Spyware_ye_3
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]00ce0adf1bbaed9fc1ee917b1bb8e8 }


condition:
	$a0
}