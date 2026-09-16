rule Win_Trojan_Subsys_19
{
strings:
	$a0 = { f5676e2b77d7120b0a8583b8fad175fca11bc41823f4f5d20d979006216b841f536dc513770a4b83039943a934b2f874 }


condition:
	$a0
}