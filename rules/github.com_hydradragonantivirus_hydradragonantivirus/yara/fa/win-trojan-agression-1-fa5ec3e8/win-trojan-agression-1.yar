rule Win_Trojan_Agression_1
{
strings:
	$a0 = { 4400ba8000be130433ff8edfff0cad5eb1062bf3d3e08ec05650b8ae01500e560e1fe887008ed9 }


condition:
	$a0
}