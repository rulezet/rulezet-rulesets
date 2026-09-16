rule Win_Trojan_Trojan_72
{
strings:
	$a0 = { 4d5a12005201411be006780cffff992f }


condition:
	$a0
}