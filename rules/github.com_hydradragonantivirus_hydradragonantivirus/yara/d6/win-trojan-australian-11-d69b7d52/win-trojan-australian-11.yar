rule Win_Trojan_Australian_11
{
strings:
	$a0 = { 5b81eb0601e421a2ff00b0fee621be010189f7fbf433c08ed089c48cc88ed88f04ff355883 }


condition:
	$a0
}