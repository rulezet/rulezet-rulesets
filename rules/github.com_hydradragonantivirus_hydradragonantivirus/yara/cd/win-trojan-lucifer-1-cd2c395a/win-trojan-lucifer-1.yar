rule Win_Trojan_Lucifer_1
{
strings:
	$a0 = { 40535b565e0a38535be80f005787fe21eb9be4001dae1252518466455eeb089ff1963c0ff1e3848bf622db801c77f2 }


condition:
	$a0
}