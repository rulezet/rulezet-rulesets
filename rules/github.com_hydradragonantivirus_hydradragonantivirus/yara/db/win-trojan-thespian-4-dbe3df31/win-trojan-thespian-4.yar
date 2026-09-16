rule Win_Trojan_Thespian_4
{
strings:
	$a0 = { b440b9d6018d960600cd21e80500b43ecd21c38db61100b9a601803400464975f9c3 }


condition:
	$a0
}