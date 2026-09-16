rule Win_Trojan_Highlander_1
{
strings:
	$a0 = { de7505b4ede90b0180fc4b7403e903013cff750532 }


condition:
	$a0
}