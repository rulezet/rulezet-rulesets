rule Win_Trojan_OneMinute_1
{
strings:
	$a0 = { 668bd9d348033572769b9617882d7e6633e4cc5b51fe744450880f472301a8a6fb9be87b382074 }


condition:
	$a0
}