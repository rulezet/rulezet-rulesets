rule Win_Trojan_CARBUNCA_1
{
strings:
	$a0 = { b96d02ba0001b440cd21b43ecd21ba6102b90300b80143cd21b41abafd03cd21b44eba7102cd }


condition:
	$a0
}