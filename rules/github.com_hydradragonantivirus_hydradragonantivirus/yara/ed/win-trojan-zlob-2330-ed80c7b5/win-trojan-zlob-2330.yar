rule Win_Trojan_Zlob_2330
{
strings:
	$a0 = { 6a0aff15???04000506a006a00ff156c?0400050e8??f?ffff50ff15???04000cccccccccccccccccccccccccccccccc515?8b }


condition:
	$a0
}