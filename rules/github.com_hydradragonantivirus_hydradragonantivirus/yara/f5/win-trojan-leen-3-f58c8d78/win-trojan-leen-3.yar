rule Win_Trojan_Leen_3
{
strings:
	$a0 = { b82135cd21891e????8c06????b82125ba????cd21[2-3]3da1fe740a3d004b7406ea }


condition:
	$a0
}