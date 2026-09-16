rule Win_Trojan_Yankee_2
{
strings:
	$a0 = { 5b5383eb44c32e80bf010000740681fcf0ff72e58cd848 }


condition:
	$a0
}