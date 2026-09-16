rule Win_Trojan_Mouse_1
{
strings:
	$a0 = { b7005589e5b800019a8006b70081ec00019a080bb70009c07503e986008dbe00ff16576a019ab80ab700bf6007 }


condition:
	$a0
}