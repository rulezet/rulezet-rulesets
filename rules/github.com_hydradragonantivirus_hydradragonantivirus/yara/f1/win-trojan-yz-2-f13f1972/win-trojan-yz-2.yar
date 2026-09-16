rule Win_Trojan_YZ_2
{
strings:
	$a0 = { fc8db76401b2098d8f64062bce2e301446e2fafbc3595a }


condition:
	$a0
}