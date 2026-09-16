rule Win_Trojan_SillyC_245
{
strings:
	$a0 = { e800005d81ed0701fc8db6a701bf0001a5a58d96bc01b41acd21b920008d969d01b44ecd2172628d96da01b43db002cd21 }


condition:
	$a0
}