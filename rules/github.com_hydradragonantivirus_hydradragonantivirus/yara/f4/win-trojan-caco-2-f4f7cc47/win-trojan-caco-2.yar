rule Win_Trojan_Caco_2
{
strings:
	$a0 = { dbb8fffdcd215e33d25681fb414c75232e3aaceb0c771f }


condition:
	$a0
}