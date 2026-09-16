rule Win_Trojan_Invictus_1
{
strings:
	$a0 = { 494e5649435455532e444c4c0500dd88060000fb030000748a020000 }


condition:
	$a0
}