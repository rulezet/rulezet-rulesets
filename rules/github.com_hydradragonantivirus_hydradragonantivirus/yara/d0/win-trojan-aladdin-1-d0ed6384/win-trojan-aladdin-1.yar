rule Win_Trojan_Aladdin_1
{
strings:
	$a0 = { b440b973038d960600cd21e80500b43ecd21c38db61f00b93503803400464975f9c3 }


condition:
	$a0
}