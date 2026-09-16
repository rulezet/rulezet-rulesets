rule Win_Trojan_Malmsey_3
{
strings:
	$a0 = { 0200ba8002cd21813e80028bf69c7413998bcab80042cd21b440b9f00190ba0001cd21b43ecd21 }


condition:
	$a0
}