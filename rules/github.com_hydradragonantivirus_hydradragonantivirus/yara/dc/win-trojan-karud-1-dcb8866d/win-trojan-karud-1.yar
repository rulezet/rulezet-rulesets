rule Win_Trojan_Karud_1
{
strings:
	$a0 = { 8d45b8895dd850535353ff75fc895ddcff15a8070100 }


condition:
	$a0
}