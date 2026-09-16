rule Win_Trojan_Poss_3
{
strings:
	$a0 = { 0e8000b80042e82100ba0000b97708b440e81600e9b9fd33c08ec0268e16f601268b26f4015807 }


condition:
	$a0
}