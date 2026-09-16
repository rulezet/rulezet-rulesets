rule Win_Trojan_Packed_170
{
strings:
	$a0 = { 6033f681f620304000832d??204000046a026a0056e8????000083e8037c0b807e????0f84??050000cc8046????ebe0 }


condition:
	$a0
}