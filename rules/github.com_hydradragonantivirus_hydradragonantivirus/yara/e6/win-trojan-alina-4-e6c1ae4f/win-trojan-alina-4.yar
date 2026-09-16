rule Win_Trojan_Alina_4
{
strings:
	$a0 = { 2d395d7b31332c31397d5c5e5b412d5a612d7a5c73[0-5]302c32367d }


condition:
	$a0
}