rule Win_Trojan_Krad_1
{
strings:
	$a0 = { 514844595501084e5184590a0c0a2a0dcf0265240f }


condition:
	$a0
}