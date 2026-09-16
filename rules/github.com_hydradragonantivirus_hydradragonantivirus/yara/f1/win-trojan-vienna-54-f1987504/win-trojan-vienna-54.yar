rule Win_Trojan_Vienna_54
{
strings:
	$a0 = { b440b985028bd681eaf601cd21721f3d }


condition:
	$a0
}