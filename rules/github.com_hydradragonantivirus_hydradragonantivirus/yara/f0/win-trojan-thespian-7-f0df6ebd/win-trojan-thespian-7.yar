rule Win_Trojan_Thespian_7
{
strings:
	$a0 = { b440b96c028d960600cd21e80500b43ecd21c38db61100b93c02803400464975f9c3 }


condition:
	$a0
}