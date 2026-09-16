rule Win_Trojan_Demo_2
{
strings:
	$a0 = { 66813c1a504575dd8b74137803f38b4e0c8b041925dfdfdfdf3d4b45524e }


condition:
	$a0
}