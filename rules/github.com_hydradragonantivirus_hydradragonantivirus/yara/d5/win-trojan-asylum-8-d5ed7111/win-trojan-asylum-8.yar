rule Win_Trojan_Asylum_8
{
strings:
	$a0 = { 5068ee31400068ee31400068363040008d8578feffff50e81e01000083c4286a00508d8578feffff50ffb574feffffe854010000 }


condition:
	$a0
}