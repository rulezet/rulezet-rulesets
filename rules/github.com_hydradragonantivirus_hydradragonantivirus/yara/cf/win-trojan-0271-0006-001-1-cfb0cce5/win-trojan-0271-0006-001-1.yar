rule Win_Trojan__0271_0006_001_1
{
strings:
	$a0 = { 3f03c8890e0401b440ba0001b90c00cd21b440ba9d01b99100cd21b43ecd21b44feb86b409 }


condition:
	$a0
}