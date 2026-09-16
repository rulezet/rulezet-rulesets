rule Win_Trojan_Poppy_1
{
strings:
	$a0 = { 9090cd2032004000b800d70000cd20320040005acd204a01010083c40c5acd205201010083c4 }


condition:
	$a0
}