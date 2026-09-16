rule Win_Trojan_Yaunch_1
{
strings:
	$a0 = { 012bdb8a058a2032c48805473bfa730a4383fb0a72ed }


condition:
	$a0
}