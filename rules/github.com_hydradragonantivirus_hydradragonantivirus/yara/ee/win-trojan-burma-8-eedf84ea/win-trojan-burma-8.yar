rule Win_Trojan_Burma_8
{
strings:
	$a0 = { 9033c990ba9e0090cd2190b740909390ba000190b9f40290cd2190c3b409ba3d03cd21c3 }


condition:
	$a0
}