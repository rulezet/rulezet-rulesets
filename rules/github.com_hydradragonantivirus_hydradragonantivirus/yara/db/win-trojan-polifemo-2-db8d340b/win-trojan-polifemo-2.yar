rule Win_Trojan_Polifemo_2
{
strings:
	$a0 = { 3db002ba9e00cd217235a33b01e830003d00007507e868 }


condition:
	$a0
}