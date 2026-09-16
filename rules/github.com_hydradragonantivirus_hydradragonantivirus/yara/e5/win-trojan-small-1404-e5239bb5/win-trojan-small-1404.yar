rule Win_Trojan_Small_1404
{
strings:
	$a0 = { 81eca40000005355565768483240006a }

	$a1 = { 494c454f505453000000005265 }


condition:
	$a0 and $a1
}