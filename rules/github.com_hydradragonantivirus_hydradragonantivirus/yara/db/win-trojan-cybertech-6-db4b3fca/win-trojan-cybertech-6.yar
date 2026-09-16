rule Win_Trojan_CyberTech_6
{
strings:
	$a0 = { e800005d81ed0700502e8b86e0002e8b9ee2002ea300012e891e0201b41aba00fdcd21b44e8d96da0033c9cd217303e9 }


condition:
	$a0
}