rule Win_Trojan_Flex_1
{
strings:
	$a0 = { 0b008bfeb9ca01ac34a4aae2fac35b464c45585d }


condition:
	$a0
}