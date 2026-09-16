rule Win_Trojan_Koths_3
{
strings:
	$a0 = { b9a3128bd58be987ca87e98bd58be987ca87e9fc8bd58be987ca87e98bd58be987ca87e9ac8bd58be987ca87e98bd58be987ca87e934??8bd58be987ca87e98bd58be987ca87e9aa8bd58be987ca87e98bd58be987ca87e9e2ca }


condition:
	$a0
}