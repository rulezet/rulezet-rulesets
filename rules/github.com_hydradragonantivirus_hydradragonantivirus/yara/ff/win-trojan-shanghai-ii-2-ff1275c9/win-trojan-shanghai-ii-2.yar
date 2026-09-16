rule Win_Trojan_Shanghai_II_2
{
strings:
	$a0 = { 6c01ca152a2e2a00434f4dd4455845e9dc03e9af043500fcbf0001be1b0101dee9570690 }


condition:
	$a0
}