rule Win_Trojan_Vriest_1
{
strings:
	$a0 = { bf0001b91000f2a4b80001ffe0ff554fffb489cd213d23017432b82135cd218c06 }


condition:
	$a0
}