rule Win_Trojan_Agent_35382
{
strings:
	$a0 = { 50735c4472697665725c693338365c4b696c6c65722e706462 }


condition:
	$a0
}