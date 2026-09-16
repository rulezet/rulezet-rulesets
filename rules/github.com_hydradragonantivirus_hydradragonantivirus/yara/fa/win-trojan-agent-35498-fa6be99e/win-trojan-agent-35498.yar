rule Win_Trojan_Agent_35498
{
strings:
	$a0 = { 666e3d433a5c57494e444f57535c73797374656d5c786363[0-20]2e657865 }


condition:
	$a0
}