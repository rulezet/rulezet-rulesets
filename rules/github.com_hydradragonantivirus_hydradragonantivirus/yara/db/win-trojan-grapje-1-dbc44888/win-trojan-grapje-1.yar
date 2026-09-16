rule Win_Trojan_Grapje_1
{
strings:
	$a0 = { c501cd214b8bcbe306b44fcd21e2fa }


condition:
	$a0
}