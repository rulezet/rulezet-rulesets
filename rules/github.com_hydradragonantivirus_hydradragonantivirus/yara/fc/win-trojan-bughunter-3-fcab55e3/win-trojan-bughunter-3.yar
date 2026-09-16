rule Win_Trojan_BugHunter_3
{
strings:
	$a0 = { 960902cd21b905008db6f701bf0001f3a4b44eb907008d96f101cd217303e9ac00b8014332 }


condition:
	$a0
}