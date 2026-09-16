rule Win_Trojan_Babylonia_5
{
strings:
	$a0 = { 6833010100e8a9e8ffff83c410c3608b4424248b4c24286a005150ffb5a4140000ff95271600 }


condition:
	$a0
}