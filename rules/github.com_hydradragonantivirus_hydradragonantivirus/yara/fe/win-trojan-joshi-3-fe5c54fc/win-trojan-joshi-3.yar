rule Win_Trojan_Joshi_3
{
strings:
	$a0 = { 8a2e1e7c8a0e1f7cb6008a16207c }


condition:
	$a0
}