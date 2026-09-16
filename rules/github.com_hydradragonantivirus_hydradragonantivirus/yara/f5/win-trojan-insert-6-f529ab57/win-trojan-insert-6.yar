rule Win_Trojan_Insert_6
{
strings:
	$a0 = { 40a30a01b91101bf1101be0000f3a4bf1701e83e00b440b91101ba1101cd211f5e5a59075f }


condition:
	$a0
}