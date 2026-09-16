rule Win_Trojan_Jerusalem_58
{
strings:
	$a0 = { b82135cd21891e????8c06????b82125ba????cd2107bb4f02896f04896f08896f0c268e062c }


condition:
	$a0
}