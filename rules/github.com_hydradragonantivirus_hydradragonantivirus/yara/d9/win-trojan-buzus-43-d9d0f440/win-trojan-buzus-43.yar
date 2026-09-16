rule Win_Trojan_Buzus_43
{
strings:
	$a0 = { e8fb940000e916feffffcccccccc8b4c2404f7c10300000074248a0183c10184 }


condition:
	$a0
}