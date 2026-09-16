rule Win_Trojan_Anarchy_6
{
strings:
	$a0 = { 2159722797b440bb060099cd21721c3bc1721883f9fff87512970bc0740db440f7d94acd21 }


condition:
	$a0
}