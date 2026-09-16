rule Win_Trojan__0245_0001_001_1
{
strings:
	$a0 = { b8004233c933d2cc8d964c05b440b91a00ccfe864b05b801575a59ccb43ecc585a59ccb44fe9 }


condition:
	$a0
}