rule Win_Trojan_Escort_2
{
strings:
	$a0 = { 90b44fcd21eb9dfcbf2c01b000b90c00f2aeb00daab80c002bc12ea22b01be2b01cd2eb8004c }


condition:
	$a0
}