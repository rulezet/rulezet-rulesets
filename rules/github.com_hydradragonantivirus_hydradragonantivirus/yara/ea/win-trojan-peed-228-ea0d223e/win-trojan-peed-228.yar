rule Win_Trojan_Peed_228
{
strings:
	$a0 = { fcbd7273030089e67341ff1537647400e88147c3ff8f0537377600f7d3685359 }


condition:
	$a0
}