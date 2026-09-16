rule Win_Trojan_V_118
{
strings:
	$a0 = { b82135cd21891e????8c06????b425ba????cd21b0d38bd71fcd212e8b8681002e8b9e7f000e5929 }


condition:
	$a0
}