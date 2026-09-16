rule Win_Trojan_Protect_2
{
strings:
	$a0 = { 8be5b82173cd213c717503e98200b449cd2133db8edba113044848a31304b106d3e0 }


condition:
	$a0
}