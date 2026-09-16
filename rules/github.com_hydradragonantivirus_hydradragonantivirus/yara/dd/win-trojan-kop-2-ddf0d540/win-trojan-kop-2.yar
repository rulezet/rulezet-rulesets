rule Win_Trojan_Kop_2
{
strings:
	$a0 = { 01030055df00000000ffff700800001a000000040000007008 }


condition:
	$a0
}