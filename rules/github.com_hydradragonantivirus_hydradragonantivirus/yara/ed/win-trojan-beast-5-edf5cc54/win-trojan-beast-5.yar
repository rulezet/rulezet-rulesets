rule Win_Trojan_Beast_5
{
strings:
	$a0 = { cd21720cb440b90300ba470003d6cd21 }


condition:
	$a0
}