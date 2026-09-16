rule Win_Trojan_R_26
{
strings:
	$a0 = { 35cd21bff503891ef5038c06f703ba1b01b425cd2189facd273d004b74083d003d7403e9cc02e99302556e6b6e6f }


condition:
	$a0
}