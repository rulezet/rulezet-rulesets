rule Win_Trojan_Silly_52
{
strings:
	$a0 = { 010100558e00000000ffff000000000c020000040000001103 }


condition:
	$a0
}