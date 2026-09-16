rule Win_Trojan_QD335_1
{
strings:
	$a0 = { 039caa052e899c32002e8b9ca8052e899c30008cc3ff4f72206a6e2c6246ff8bfd83c732b92000f3a4bf00018bf583 }


condition:
	$a0
}