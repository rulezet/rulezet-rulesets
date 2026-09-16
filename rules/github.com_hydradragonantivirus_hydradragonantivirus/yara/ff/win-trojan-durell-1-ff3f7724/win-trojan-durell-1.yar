rule Win_Trojan_Durell_1
{
strings:
	$a0 = { bbc52ed1ebd1ebd1ebd1eb03c38ed88ec0e81f1fc606d01b00b40fcd10a2c71b3c077273ba861bb409cd21eb6590 }


condition:
	$a0
}