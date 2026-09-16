rule Win_Trojan_Eumel_2
{
strings:
	$a0 = { e800005d81ed0a018db62501568bfe8b968302b95e01fcac32c2aae2fac3 }


condition:
	$a0
}