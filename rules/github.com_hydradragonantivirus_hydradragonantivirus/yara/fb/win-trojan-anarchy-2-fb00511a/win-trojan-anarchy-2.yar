rule Win_Trojan_Anarchy_2
{
strings:
	$a0 = { f4c5597f85c9868ad32627f22f95f2379790549791797927f8970b6fbac91fd3f23f93d2fa3f9373 }


condition:
	$a0
}