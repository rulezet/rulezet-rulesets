rule Win_Trojan_Script_8
{
strings:
	$a0 = { 4348454154454e47494e4507 }


condition:
	$a0
}