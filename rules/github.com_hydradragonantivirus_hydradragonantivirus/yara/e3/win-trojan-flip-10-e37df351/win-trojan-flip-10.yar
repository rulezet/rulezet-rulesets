rule Win_Trojan_Flip_10
{
strings:
	$a0 = { bbfdb31fb97666b2f281c17fa2eb0f8fa28fa28fa28fa28fa28fa28fa28f0097504e43eb }


condition:
	$a0
}