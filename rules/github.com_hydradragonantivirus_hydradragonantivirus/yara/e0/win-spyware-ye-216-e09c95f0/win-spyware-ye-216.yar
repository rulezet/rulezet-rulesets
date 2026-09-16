rule Win_Spyware_ye_216
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]d51bdf34f097c2f49ec3eed8f89dd5 }


condition:
	$a0
}