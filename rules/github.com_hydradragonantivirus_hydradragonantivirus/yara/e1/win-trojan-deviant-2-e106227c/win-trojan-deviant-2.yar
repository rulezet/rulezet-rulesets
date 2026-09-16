rule Win_Trojan_Deviant_2
{
strings:
	$a0 = { 018aa6b902478a0532c48805e2f733f65e81fefe0074 }


condition:
	$a0
}