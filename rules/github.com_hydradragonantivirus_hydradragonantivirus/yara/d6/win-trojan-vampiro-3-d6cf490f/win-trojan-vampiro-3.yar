rule Win_Trojan_Vampiro_3
{
strings:
	$a0 = { b904008d964b04cd21b80242b90000ba0000cd213e83868903035bb440b9e8038d960001cd21 }


condition:
	$a0
}