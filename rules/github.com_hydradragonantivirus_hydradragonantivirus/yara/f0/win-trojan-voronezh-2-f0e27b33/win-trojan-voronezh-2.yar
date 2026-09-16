rule Win_Trojan_Voronezh_2
{
strings:
	$a0 = { 067503e996013de2f073f8b9300603c1a32d0633d2b440cd21e8a001b103ba2c06b440cd21 }


condition:
	$a0
}