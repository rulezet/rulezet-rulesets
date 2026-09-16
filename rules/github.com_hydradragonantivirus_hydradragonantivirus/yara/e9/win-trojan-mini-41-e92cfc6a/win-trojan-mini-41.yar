rule Win_Trojan_Mini_41
{
strings:
	$a0 = { b98000be8000bf7ffff3a4b81f028bc82d0001a3fa00030e1d02890ef80003c8890ef6008bc8be00018b3ef800f3a4b003a20101f9ba1602b44eb92000cd }


condition:
	$a0
}