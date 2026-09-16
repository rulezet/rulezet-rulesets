rule Win_Trojan_K_28
{
strings:
	$a0 = { 03cd21b4408b1ef6028b0e6a02ba1001cd21b442b0008b1ef602b90000ba0000cd21b4408b1e }


condition:
	$a0
}