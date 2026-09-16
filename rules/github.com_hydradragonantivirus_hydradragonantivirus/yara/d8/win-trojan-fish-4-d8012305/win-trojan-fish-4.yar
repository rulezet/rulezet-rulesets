rule Win_Trojan_Fish_4
{
strings:
	$a0 = { 13044848a31304b106d3e08ec0a3db7cc706d97c6d00b90001fcf3a52eff2ed97c2e8a261500 }


condition:
	$a0
}