rule Win_Trojan_Shadow_2
{
strings:
	$a0 = { 0200cd21505351525556571e06e800005e83ee0cbb2c002e8b542a2e8b0033c22e890083c30281fba1047cefeb02 }


condition:
	$a0
}