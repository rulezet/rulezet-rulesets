rule Win_Trojan_F_21
{
strings:
	$a0 = { fc99750333c9cf80fc4e75082ec606750001eb2080fc4f }


condition:
	$a0
}