rule Win_Trojan_MyLife_5
{
strings:
	$a0 = { 7a6172793230 }

	$a1 = { 40656d61696c2e636f6d }


condition:
	$a0 and $a1
}