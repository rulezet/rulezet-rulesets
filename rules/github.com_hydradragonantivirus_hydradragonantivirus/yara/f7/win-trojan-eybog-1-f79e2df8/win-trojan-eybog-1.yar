rule Win_Trojan_Eybog_1
{
strings:
	$a0 = { 536c656570 }

	$a1 = { 4765744c6f63616c54696d65 }

	$a2 = { 47657453746172747570496e666f41 }

	$a3 = { 487474704f70656e5265717565737441 }

	$a4 = { 3132372e302e302e31[0-23]4d6f7a696c6c612f342e30 }


condition:
	$a0 and $a1 and $a2 and $a3 and $a4
}