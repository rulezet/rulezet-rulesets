rule Win_Trojan_Lurid_1
{
strings:
	$a0 = { 5d81ed03018aa62b0180fc0074168dbe2b018bf78d8ebb032bcf8aa62a01ac32c4aae2fae9 }


condition:
	$a0
}