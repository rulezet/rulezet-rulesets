rule Win_Trojan_Albania_2
{
strings:
	$a0 = { a300018a4615a20201a12c008ec0 }


condition:
	$a0
}