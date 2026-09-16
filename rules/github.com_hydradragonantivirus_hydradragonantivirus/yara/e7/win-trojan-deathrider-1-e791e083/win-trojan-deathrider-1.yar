rule Win_Trojan_Deathrider_1
{
strings:
	$a0 = { 01b80807cd13b000e670e671fec0ebf8b419cd213c00 }


condition:
	$a0
}