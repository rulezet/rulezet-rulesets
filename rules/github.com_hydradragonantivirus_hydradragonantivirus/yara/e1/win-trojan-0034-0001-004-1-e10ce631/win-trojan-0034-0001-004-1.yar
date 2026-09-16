rule Win_Trojan__0034_0001_004_1
{
strings:
	$a0 = { 0a5253568bddfec7e8d4f7b4405a5bcd21b440b916095acd215f0726804d0640b43ecd21c3 }


condition:
	$a0
}