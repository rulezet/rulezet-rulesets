rule Win_Trojan_Pbox_1
{
strings:
	$a0 = { 68ff00000068[0-2]4000e855[0-2]0068[0-2]4000e8[0-2]000068[0-2]400068 }

	$a1 = { 204000e830 }

	$a2 = { 000083f8ff75 }


condition:
	$a0 and $a1 and $a2
}