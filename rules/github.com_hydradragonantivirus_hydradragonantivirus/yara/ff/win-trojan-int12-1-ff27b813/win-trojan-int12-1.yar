rule Win_Trojan_Int12_1
{
strings:
	$a0 = { 8c0632040e07be2404bf3404a5a5a5a5b81235cd21891e44048c0646041eb82135cd21061f8bd3b81225cd211fb4 }


condition:
	$a0
}