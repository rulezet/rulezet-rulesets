rule Win_Trojan_Form_1
{
strings:
	$a0 = { b801038b0e49008b164b00cd13 }


condition:
	$a0
}