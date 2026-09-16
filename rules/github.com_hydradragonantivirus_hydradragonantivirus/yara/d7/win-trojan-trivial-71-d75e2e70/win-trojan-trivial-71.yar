rule Win_Trojan_Trivial_71
{
strings:
	$a0 = { 90ba0001cd21b457b0015a59cd21b43ecd21b44fcd }


condition:
	$a0
}