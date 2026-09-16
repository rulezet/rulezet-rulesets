rule Win_Trojan_Muze_4
{
strings:
	$a0 = { b30050e9d0fbb8f490abb91000ba120ab440e816f9c706140b9c01cd03be0000bf120ab97a }


condition:
	$a0
}