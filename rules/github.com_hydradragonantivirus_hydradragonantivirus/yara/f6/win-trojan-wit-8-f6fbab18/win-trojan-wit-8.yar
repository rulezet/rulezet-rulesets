rule Win_Trojan_Wit_8
{
strings:
	$a0 = { e802a3ea02a1ec02a30f038a261f038b16ea0203160f0381c20001cd2183c21e891611038b }


condition:
	$a0
}