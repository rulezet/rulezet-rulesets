rule Win_Spyware_ye_211
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]d01eda2feb8a3d6f11bee1cbeb8838 }


condition:
	$a0
}