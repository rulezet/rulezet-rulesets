rule Win_Trojan_Milde_1
{
strings:
	$a0 = { b901b44eb90b11cd21907302eb11e85000ba8000b44fcd21907302eb02ebefb42acd213c05740bb409ba3802cd21b4 }


condition:
	$a0
}