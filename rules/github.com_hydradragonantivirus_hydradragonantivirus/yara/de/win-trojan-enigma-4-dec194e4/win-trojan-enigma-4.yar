rule Win_Trojan_Enigma_4
{
strings:
	$a0 = { 0781ea030103d3b91000b44fcd21 }


condition:
	$a0
}