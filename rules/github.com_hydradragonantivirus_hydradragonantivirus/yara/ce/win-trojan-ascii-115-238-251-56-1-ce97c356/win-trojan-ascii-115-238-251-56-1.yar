rule Win_Trojan_Ascii_115_238_251_56_1
{
strings:
	$a0 = { 3131352e3233382e3235312e3536 }


condition:
	$a0
}