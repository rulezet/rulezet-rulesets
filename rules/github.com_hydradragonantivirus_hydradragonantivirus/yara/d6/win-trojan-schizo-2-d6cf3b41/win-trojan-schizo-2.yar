rule Win_Trojan_Schizo_2
{
strings:
	$a0 = { 058d009a0e028d00b007b9ff00ba0000cd26b006b9ff00ba0000cd26b005b9ff00ba0000cd26 }


condition:
	$a0
}