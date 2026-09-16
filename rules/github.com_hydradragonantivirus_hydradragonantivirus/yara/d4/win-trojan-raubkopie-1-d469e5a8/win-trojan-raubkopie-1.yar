rule Win_Trojan_Raubkopie_1
{
strings:
	$a0 = { 0500013d0002720425ff0142b104d3e8 }


condition:
	$a0
}