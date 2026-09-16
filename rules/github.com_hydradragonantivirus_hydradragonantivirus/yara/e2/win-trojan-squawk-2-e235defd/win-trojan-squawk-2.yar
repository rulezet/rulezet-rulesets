rule Win_Trojan_Squawk_2
{
strings:
	$a0 = { a35f03b440b9540333d2e83efe7303eb7b90b8004233d28b }


condition:
	$a0
}