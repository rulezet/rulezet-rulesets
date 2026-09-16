rule Win_Trojan_Hortiga_3
{
strings:
	$a0 = { 57696e39782e68307274696761 }

	$a1 = { 436f646564206279207c5a616e202d20697a616e4067616c617879636f }


condition:
	$a0 and $a1
}