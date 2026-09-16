rule Win_Trojan_Gen_146
{
strings:
	$a0 = { 2500047e5abd1eb9febb1000e84c0318bceac7c7d29ae2b0a0c7d4f601b1fd817d02b2842918f8 }


condition:
	$a0
}