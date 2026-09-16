rule Win_Trojan_Sisoruen_1
{
strings:
	$a0 = { 3dcd2193e8b100b4408d966f02b91d00cd215ab80143b90300cd21b43ecd21ebae8d96c60252 }


condition:
	$a0
}