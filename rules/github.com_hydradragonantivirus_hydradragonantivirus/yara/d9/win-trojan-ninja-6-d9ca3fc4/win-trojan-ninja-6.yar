rule Win_Trojan_Ninja_6
{
strings:
	$a0 = { 84008b1e860026a34a0526891e4c05c7068400c2008c0686002e81bc92044d5a741c }


condition:
	$a0
}