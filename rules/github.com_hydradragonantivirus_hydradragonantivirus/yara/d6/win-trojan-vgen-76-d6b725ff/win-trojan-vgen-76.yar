rule Win_Trojan_Vgen_76
{
strings:
	$a0 = { b435cd2126813e050134127509ba4902b409cd21cd20b009b435cd218c060e01891e0c01ba1401b009b425cd21b0 }


condition:
	$a0
}