rule Win_Trojan_Vicky_1
{
strings:
	$a0 = { 03b440e83cfec3b8024233d28bcae831fec3b8004233 }


condition:
	$a0
}