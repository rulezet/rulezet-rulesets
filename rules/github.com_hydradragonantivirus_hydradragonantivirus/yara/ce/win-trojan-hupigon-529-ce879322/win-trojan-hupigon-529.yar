rule Win_Trojan_Hupigon_529
{
strings:
	$a0 = { 12c0ec5c54bca600f2a98401c5a47d28d0d41b848208605a34b96043004d4b3ffccf7dd9b6cf4dcd341e613cec1a6261c64a1387b71d96670dfc2cc40ae3f92cf44b967e0bb073fa0057cf7214aa }


condition:
	$a0
}