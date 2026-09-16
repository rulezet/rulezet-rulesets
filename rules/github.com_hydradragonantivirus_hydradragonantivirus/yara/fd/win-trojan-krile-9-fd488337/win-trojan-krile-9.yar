rule Win_Trojan_Krile_9
{
strings:
	$a0 = { b837b6de4d2d3cf71a28f467fe186a9867cc5bb88cd3153375813ee80f009ae8f9ff9a9ceb019a }


condition:
	$a0
}