rule Win_Spyware_ye_135
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]844a8e5b9fc6f19bc5ea9507afd48c }


condition:
	$a0
}