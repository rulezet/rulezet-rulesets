rule Win_Spyware_ye_55
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]34fa3e8b4f76214b751a45b7df843c }


condition:
	$a0
}