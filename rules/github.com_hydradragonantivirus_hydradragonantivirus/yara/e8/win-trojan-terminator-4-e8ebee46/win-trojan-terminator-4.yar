rule Win_Trojan_Terminator_4
{
strings:
	$a0 = { 33c932c0e82501ba1206b91600e82401595a32c0e8150133d2b9a805e81501fa }


condition:
	$a0
}