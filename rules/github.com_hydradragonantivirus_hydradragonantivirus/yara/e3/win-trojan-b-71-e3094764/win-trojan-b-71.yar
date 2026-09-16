rule Win_Trojan_B_71
{
strings:
	$a0 = { 33d2cd13c333c08ed8a14c002ea3 }


condition:
	$a0
}