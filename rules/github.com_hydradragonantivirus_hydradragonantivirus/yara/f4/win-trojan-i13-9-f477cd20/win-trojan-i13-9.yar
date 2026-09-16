rule Win_Trojan_I13_9
{
strings:
	$a0 = { 8134ca094646e2f8c3cc16721a07c4eb34ebc4be59ccb1eb3c0728e480542fc927468fe20a46d182870a2f6b0aca243209 }


condition:
	$a0
}