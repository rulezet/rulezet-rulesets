rule Win_Trojan_V_116
{
strings:
	$a0 = { b82135cd21891e????8c06????b82125ba????cd21071fbf00febe4a01b90d }


condition:
	$a0
}