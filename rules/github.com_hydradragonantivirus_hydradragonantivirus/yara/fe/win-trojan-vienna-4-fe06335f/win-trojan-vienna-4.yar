rule Win_Trojan_Vienna_4
{
strings:
	$a0 = { b440b900048bd681eac102cd21721f3d }


condition:
	$a0
}