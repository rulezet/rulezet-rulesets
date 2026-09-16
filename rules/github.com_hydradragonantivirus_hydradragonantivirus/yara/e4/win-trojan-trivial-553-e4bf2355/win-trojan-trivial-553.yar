rule Win_Trojan_Trivial_553
{
strings:
	$a0 = { b92700be????89f7ac3206????aae2f8c3 }


condition:
	$a0
}