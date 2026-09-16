rule Win_Trojan_V_91
{
strings:
	$a0 = { 06e703a1d903a3e903a1db03a3eb03a1dd03a3ed03a1df03a3ef03b42fcd21891ef1038c06f303ba5704b41acd }


condition:
	$a0
}