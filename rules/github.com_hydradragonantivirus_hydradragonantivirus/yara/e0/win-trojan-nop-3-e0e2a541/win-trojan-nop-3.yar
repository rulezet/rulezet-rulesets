rule Win_Trojan_Nop_3
{
strings:
	$a0 = { 0200558e0000010002006d030000c7000000020000000b03 }


condition:
	$a0
}