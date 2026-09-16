rule Win_Trojan_Pocks_1
{
strings:
	$a0 = { b440b9a8018d960600cd21e80500b43ecd21c38db61f00b96a01803400464975f9c3 }


condition:
	$a0
}