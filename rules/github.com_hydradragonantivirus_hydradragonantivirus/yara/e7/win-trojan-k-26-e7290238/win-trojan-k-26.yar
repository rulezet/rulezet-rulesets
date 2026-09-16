rule Win_Trojan_K_26
{
strings:
	$a0 = { 022ea20001a0d7022ea20101a0d8022ea20201b90001bb00002e8a078887da0243e2f6baba02b92000b44ecd2173 }


condition:
	$a0
}