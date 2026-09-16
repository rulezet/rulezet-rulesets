rule Win_Trojan_V_70
{
strings:
	$a0 = { bbfeefcd213d4d53750332c0c3b0ffc3b452cd2126 }


condition:
	$a0
}