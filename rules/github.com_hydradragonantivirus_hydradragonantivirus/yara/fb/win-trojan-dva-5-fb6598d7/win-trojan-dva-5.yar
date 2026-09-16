rule Win_Trojan_DVA_5
{
strings:
	$a0 = { 8bf281ee0301c35ee98100b42fcd218c84d803899cda0333d28bd681c2ed0281c200100e1fb41acd218994d603c3 }


condition:
	$a0
}