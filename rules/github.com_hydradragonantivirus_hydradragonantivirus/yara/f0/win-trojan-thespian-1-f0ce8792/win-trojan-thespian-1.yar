rule Win_Trojan_Thespian_1
{
strings:
	$a0 = { b440b939018d960600cd21e80500b43ecd21c38db61700b90301803400464975f9c3 }


condition:
	$a0
}