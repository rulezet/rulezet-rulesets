rule Win_Trojan_Murphy_6
{
strings:
	$a0 = { 1f81ee5204b9c80541f3a4b462cd21 }


condition:
	$a0
}