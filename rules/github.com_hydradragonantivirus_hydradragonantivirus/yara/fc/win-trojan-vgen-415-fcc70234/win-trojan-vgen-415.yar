rule Win_Trojan_VGEN_415
{
strings:
	$a0 = { ff8b550280ee05b426cd218b6d2cb44abb8a00cd21b452cd21268b5ffe8cc8488cd98edb438bd3035d030bed75243b }


condition:
	$a0
}