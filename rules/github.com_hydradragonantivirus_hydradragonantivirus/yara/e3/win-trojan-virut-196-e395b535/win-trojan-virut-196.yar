rule Win_Trojan_Virut_196
{
strings:
	$a0 = { e8??000000[0-100]864500(f9|fc|66|eb|89|87|f8|f5|90)[0-15]884500c3 }


condition:
	$a0
}