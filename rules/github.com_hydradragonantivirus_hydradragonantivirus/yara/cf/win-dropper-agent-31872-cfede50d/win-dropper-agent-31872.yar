rule Win_Dropper_Agent_31872
{
strings:
	$a0 = { 6a00689046141353b88c461413e856f0ffff5056e81ff4ffff56e8a9f3ffff6a0a68d4291413a16c46141350e8aff3ffff }


condition:
	$a0
}