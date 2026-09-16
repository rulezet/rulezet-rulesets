rule Win_Trojan_Killav_153
{
strings:
	$a0 = { e805001e72e905000690558bec81ec28030000a3b8ad }

	$a1 = { 5c6b696c6c5f6b6973385c[0-7]5c4b696c6c5f4b495338 }


condition:
	$a0 and $a1
}