rule Win_Spyware_ye_96
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]5da367bc781f4a7c264b766000a5dd }


condition:
	$a0
}