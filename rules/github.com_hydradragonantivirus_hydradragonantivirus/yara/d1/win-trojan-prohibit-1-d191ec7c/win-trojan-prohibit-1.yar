rule Win_Trojan_Prohibit_1
{
strings:
	$a0 = { bb00002e8a87da05b9c605bf14002e300147e2fa }


condition:
	$a0
}