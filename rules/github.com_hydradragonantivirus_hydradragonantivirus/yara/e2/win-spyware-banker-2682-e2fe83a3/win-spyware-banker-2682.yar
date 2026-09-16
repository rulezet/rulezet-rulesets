rule Win_Spyware_Banker_2682
{
strings:
	$a0 = { 45fae069309f6b37e2e0d487a7c9f1a914dbca8482c24caf2bbbc2a4fe1ad926d5883075284880603ebbdfae460bf2418c1bb1709635adff4fd9a066e5f2b3808ae58485d64ea96857884564ccb2 }


condition:
	$a0
}