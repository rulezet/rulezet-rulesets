rule Win_Trojan_Zortech_1
{
strings:
	$a0 = { 161701b8023d9c2eff1e0f048bd80e1fba0001b94403b4409c2eff1e0f04b43e9c2eff1e0f04 }


condition:
	$a0
}