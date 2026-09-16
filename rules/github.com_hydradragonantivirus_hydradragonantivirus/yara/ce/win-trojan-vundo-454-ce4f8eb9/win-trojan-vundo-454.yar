rule Win_Trojan_Vundo_454
{
strings:
	$a0 = { 807c2408010f859a0b000060be00f000108dbe0020ffff57 }


condition:
	$a0
}