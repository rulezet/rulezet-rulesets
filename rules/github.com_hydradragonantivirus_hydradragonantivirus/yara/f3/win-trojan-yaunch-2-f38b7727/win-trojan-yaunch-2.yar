rule Win_Trojan_Yaunch_2
{
strings:
	$a0 = { 5c012bdb8a058a2032c48805473bfa }


condition:
	$a0
}