rule Win_Trojan_Gen_186
{
strings:
	$a0 = { 5589e5b800029a7c02890081ec00020ee87afbbf500a1e57bf2b050e579a620889007513bf2b050e57bf50 }


condition:
	$a0
}