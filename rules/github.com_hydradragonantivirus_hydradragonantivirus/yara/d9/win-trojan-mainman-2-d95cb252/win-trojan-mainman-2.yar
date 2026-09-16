rule Win_Trojan_Mainman_2
{
strings:
	$a0 = { 8ae68d960301cd21b43ecd21b43b8d96cb01cd }


condition:
	$a0
}