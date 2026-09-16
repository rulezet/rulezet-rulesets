rule Win_Trojan__0583_0008_001_1
{
strings:
	$a0 = { a39a03b8004233c999cd21b4405a59cd215a5980c6c8b80157cd21b43ecd21071f5e5f5a59 }


condition:
	$a0
}