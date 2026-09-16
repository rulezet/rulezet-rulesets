rule Win_Trojan_Blaze_3
{
strings:
	$a0 = { 2e65786500b42ccd2180fd00750ab002b90500ba0000cd26b44eba000131c9cd21ba9e00bf9e00b000b90c00f2aec60500b43db001cd2189c3b440ba0001b9 }


condition:
	$a0
}