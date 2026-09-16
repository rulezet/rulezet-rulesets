rule Win_Trojan_Castova_1
{
strings:
	$a0 = { 494e4964697265637462616e6b554936302e646c6c }


condition:
	$a0
}