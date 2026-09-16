rule Win_Trojan_VGEN_639
{
strings:
	$a0 = { 305f084375fabc0006ff06ed04b430cd213c041bffc6065704ffbb6000b44acd21b452cd21268b47fe8cca4a8e }


condition:
	$a0
}