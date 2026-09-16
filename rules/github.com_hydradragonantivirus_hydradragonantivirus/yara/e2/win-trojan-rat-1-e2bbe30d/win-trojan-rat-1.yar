rule Win_Trojan_RAT_1
{
strings:
	$a0 = { 66696c652e64656c6574652866696c6529 }

	$a1 = { 28636f6d6d616e64203d3d20222f3f636d645f657865632229 }


condition:
	$a0 and $a1
}