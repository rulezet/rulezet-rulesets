rule Win_Trojan_Trojan_579
{
strings:
	$a0 = { 2f6463632073656e64202431202432 }

	$a1 = { 2f2f72756e20636d64202f63206261636b642e626174 }


condition:
	$a0 and $a1
}