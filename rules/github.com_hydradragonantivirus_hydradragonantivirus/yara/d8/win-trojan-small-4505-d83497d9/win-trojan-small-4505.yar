rule Win_Trojan_Small_4505
{
strings:
	$a0 = { 8d8062867504506862343504e84900000089c7508d15744dff0152 }


condition:
	$a0
}