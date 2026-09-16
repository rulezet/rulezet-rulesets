rule Win_Trojan_Hackarmy_39
{
strings:
	$a0 = { 32585075ea640e6174652e4e789c0767696c137962381d7a3823bc681e636bc6726d7914dd30fe376e }


condition:
	$a0
}