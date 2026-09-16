rule Win_Trojan_FF_Char_1
{
strings:
	$a0 = { de8c16020389260403fa8ed6bc0003061f60061ee800005e2e8a64250e070e1f8d7c10b032aa2e8a642483c6258bfe }


condition:
	$a0
}