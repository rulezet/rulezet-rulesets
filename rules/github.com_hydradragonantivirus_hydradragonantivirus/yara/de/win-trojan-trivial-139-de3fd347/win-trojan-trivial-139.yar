rule Win_Trojan_Trivial_139
{
strings:
	$a0 = { 4eba1a01cd21b8023dba9e00cd21b74093ba0001b11ecd21c3 }


condition:
	$a0
}