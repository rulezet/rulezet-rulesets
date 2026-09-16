rule Win_Trojan_Lasky_2
{
strings:
	$a0 = { 4d5a7421b8024233c9cd21fec4a32601b440b183cd21b8004233c9cd21b440fec6b183cd }


condition:
	$a0
}