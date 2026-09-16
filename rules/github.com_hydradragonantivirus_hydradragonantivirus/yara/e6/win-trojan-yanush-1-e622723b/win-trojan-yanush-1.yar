rule Win_Trojan_Yanush_1
{
strings:
	$a0 = { 058d940501cd21b8004233d233c9cd21e806fdb4408b8cba068d949406cd21e806fde8e5fc80 }


condition:
	$a0
}