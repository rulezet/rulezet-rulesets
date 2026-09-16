rule Win_Trojan_B_92
{
strings:
	$a0 = { 8ed0bc007c8ed8a113044848a31304b105fec1d3e02dc007a37e7c8ec0be007c89f7b90001 }


condition:
	$a0
}