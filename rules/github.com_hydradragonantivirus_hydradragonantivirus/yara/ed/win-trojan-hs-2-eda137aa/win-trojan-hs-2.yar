rule Win_Trojan_HS_2
{
strings:
	$a0 = { b82135cd21891e????8c06????b425ba????cd21fb071f8b36010181c66b00bf0001b90800 }


condition:
	$a0
}