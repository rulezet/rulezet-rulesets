rule Win_Trojan_VGEN_170
{
strings:
	$a0 = { 786500ba000131c9b44ecd21ba9e00b000b90c00f2aec60500b001b43dcd2189c3ba0001b96900b440cd21b43e }


condition:
	$a0
}