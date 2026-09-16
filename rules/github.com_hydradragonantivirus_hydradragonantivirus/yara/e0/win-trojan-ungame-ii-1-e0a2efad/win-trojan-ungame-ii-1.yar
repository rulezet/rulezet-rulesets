rule Win_Trojan_Ungame_II_1
{
strings:
	$a0 = { b47bcd213cb77503e9c100b449cd21bbffffb448cd2183eb40832e020040b44acd2101d88ec026c706010008002d0f }


condition:
	$a0
}