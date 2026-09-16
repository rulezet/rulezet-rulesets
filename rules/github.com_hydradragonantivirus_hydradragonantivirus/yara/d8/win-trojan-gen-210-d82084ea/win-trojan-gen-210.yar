rule Win_Trojan_Gen_210
{
strings:
	$a0 = { d9ff89ecf1ff5dc34281ec0001c47e0606578dc3307eb016de4f00e28e053cf0e28dbe30ff }


condition:
	$a0
}