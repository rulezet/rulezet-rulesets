rule Win_Trojan_Vienna_64
{
strings:
	$a0 = { 210e1fb41aba8000cd2158c3ac3c3b }


condition:
	$a0
}