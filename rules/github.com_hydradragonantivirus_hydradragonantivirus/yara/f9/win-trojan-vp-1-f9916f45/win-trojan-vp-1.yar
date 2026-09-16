rule Win_Trojan_VP_1
{
strings:
	$a0 = { 01fcbf0001b91000f2a4b80001ffe0 }


condition:
	$a0
}