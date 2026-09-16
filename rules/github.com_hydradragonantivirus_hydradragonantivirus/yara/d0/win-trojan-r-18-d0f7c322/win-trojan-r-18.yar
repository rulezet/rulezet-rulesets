rule Win_Trojan_R_18
{
strings:
	$a0 = { 432d3e8b966c058db61c01b9280231144646e2fa }


condition:
	$a0
}