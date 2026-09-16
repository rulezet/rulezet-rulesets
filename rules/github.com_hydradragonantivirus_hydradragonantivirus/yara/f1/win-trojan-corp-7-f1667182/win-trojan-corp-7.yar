rule Win_Trojan_Corp_7
{
strings:
	$a0 = { b440b9a0028d960600cd21e80500b43ecd21c38db61f00b96202803400464975f9c3 }


condition:
	$a0
}