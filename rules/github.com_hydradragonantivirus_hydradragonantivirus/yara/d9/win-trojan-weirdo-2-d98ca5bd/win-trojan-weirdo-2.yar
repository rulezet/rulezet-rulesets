rule Win_Trojan_Weirdo_2
{
strings:
	$a0 = { 02b90400b8012bbab1cacd210568097a70cd218d7f0af3a7756704bacd21895c3f8c4441b452cd2126c55ffc8b4f03395f01740e803f4d75488cd803c140 }


condition:
	$a0
}