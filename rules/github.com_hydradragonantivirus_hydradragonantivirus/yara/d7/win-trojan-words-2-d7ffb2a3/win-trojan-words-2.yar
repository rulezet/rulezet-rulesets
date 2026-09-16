rule Win_Trojan_Words_2
{
strings:
	$a0 = { 0efe59588bc15e5d9dcf528bd6b4409c2eff1e0d005a }


condition:
	$a0
}