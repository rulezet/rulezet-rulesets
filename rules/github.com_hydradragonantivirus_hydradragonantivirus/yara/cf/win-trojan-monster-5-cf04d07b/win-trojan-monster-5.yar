rule Win_Trojan_Monster_5
{
strings:
	$a0 = { fc368b2d81ed0c01e81401eb008db60501b90400b8ff004097fcf3a4b41a8d965302cd21c686520200b44e8db67102 }


condition:
	$a0
}