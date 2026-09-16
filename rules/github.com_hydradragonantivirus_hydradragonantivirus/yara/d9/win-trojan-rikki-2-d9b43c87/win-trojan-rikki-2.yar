rule Win_Trojan_Rikki_2
{
strings:
	$a0 = { 018d0eb2082bcab440cd2133c933d2b80042cd218d36f301b0e98804582d0300894401b903 }


condition:
	$a0
}