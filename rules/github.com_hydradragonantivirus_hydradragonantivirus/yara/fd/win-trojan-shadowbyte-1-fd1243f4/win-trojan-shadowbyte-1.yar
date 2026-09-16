rule Win_Trojan_Shadowbyte_1
{
strings:
	$a0 = { 05b280b600b500b002cd13b405b200cd13b400b003cd10 }


condition:
	$a0
}