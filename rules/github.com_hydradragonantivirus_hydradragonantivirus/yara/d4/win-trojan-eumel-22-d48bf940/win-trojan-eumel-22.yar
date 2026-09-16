rule Win_Trojan_Eumel_22
{
strings:
	$a0 = { 5d81ed0a018db62501568bfe8b968602b96101fcac32c2aae2fac3 }


condition:
	$a0
}