rule Win_Trojan_Typer_1
{
strings:
	$a0 = { dac32ea12c008ed833f6813c434f750e817c024d537507817c045045740346ebe983c608561e46 }


condition:
	$a0
}