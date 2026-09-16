rule Win_Trojan_Tgasc_1
{
strings:
	$a0 = { 06e81700071f5e83ee035f4e4f2e8a042e880581ff000175f257c30e1fe81e01b42fcd212e895e002e8c4602b41aba }


condition:
	$a0
}