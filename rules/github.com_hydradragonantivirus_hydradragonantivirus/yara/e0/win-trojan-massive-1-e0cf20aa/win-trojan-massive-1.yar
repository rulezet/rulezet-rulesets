rule Win_Trojan_Massive_1
{
strings:
	$a0 = { 17772c8b0e430181c185013bc17420c6068201e92d0300a383012ac0e82a00b440b90300ba82 }


condition:
	$a0
}