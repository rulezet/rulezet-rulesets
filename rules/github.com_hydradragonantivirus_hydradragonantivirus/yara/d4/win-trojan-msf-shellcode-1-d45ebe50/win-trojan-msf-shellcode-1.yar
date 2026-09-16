rule Win_Trojan_MSF_Shellcode_1
{
strings:
	$a0 = { e8??000000[0-20]89e5[0-20]31d2[0-20]648b5230[0-20]8b520c[0-20]8b5214[0-20]8b7228[0-20]0fb74a26[0-50]8b5210[0-20]8b423c }


condition:
	$a0
}