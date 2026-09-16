rule Win_Trojan__0487_0002_000_1
{
strings:
	$a0 = { f3a4b8004233c999cd21b4408d96a40359cd21fe8ea303e9f0feb801438d969603cd21c35b5db4 }


condition:
	$a0
}