rule Win_Trojan_Lipstick_2
{
strings:
	$a0 = { 088006507429bb4c02e82a00a1a64884e803bb5b0c1e0c174201e84000b03ae8550026e835 }


condition:
	$a0
}