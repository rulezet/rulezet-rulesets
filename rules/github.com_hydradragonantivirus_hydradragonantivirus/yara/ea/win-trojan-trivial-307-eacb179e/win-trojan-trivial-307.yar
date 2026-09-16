rule Win_Trojan_Trivial_307
{
strings:
	$a0 = { b44eb92000ba2f01cd217222eb06b44fcd21721ab8013dba9e00cd218bd8b440b93500ba0001cd21b43ecd21ebe0c3 }


condition:
	$a0
}