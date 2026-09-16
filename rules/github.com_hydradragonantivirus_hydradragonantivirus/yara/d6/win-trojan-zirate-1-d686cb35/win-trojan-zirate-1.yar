rule Win_Trojan_Zirate_1
{
strings:
	$a0 = { 2135cd21891e2f028c063102b82125babc01cd21c33d4dfa75060e07b830fbcf50535780fc4b }


condition:
	$a0
}