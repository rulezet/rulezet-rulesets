rule Win_Trojan_DelFil_9
{
strings:
	$a0 = { 64656c74726565202f7920633a5c70726f6772617e315c2a2e2a }


condition:
	$a0
}