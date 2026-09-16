rule Win_Trojan_HIV_3
{
strings:
	$a0 = { 3d4e06731a585af9c3ba8c01b409cd21 }


condition:
	$a0
}