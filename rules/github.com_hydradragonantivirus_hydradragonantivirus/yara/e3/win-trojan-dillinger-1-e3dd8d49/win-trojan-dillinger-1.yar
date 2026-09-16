rule Win_Trojan_Dillinger_1
{
strings:
	$a0 = { cd211feb04eb47ebce50b9ffff8bd8b43fbabf01cd }


condition:
	$a0
}