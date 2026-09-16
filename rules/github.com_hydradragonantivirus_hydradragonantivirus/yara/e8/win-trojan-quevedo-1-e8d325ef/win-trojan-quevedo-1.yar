rule Win_Trojan_Quevedo_1
{
strings:
	$a0 = { 01b440cd21fbb801575a59cd21b43ecd21b44f }


condition:
	$a0
}