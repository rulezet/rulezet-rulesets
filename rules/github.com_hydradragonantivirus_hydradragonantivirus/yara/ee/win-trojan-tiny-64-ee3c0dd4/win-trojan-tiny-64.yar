rule Win_Trojan_Tiny_64
{
strings:
	$a0 = { a1840066a3f202b82125ba5102cd21610e1f0e07c3b003cfb440cd2133c99964894c15b602b104 }


condition:
	$a0
}