rule Win_Trojan_Hell_3
{
strings:
	$a0 = { b440b975038d960601cd21e80500b43ecd21c38db62001b93603803400464975f9c3 }


condition:
	$a0
}