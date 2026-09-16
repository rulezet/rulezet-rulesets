rule Win_Trojan_Small_4151
{
strings:
	$a0 = { eb1acd2affe350ffd0816d00c2ab233483c50283c50239ef75 }


condition:
	$a0
}