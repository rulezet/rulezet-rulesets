rule Win_Trojan_Micro_1
{
strings:
	$a0 = { a5a431c08ec0bf0303b17df3a4af750e }


condition:
	$a0
}