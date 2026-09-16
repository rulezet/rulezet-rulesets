rule Win_Spyware_4741_1
{
strings:
	$a0 = { 81c3fe8ff5f781c302700a0881c34823 }


condition:
	$a0
}