rule Win_Trojan_Vienna_53
{
strings:
	$a0 = { b440b984028bd681eaf601cd21721f3d }


condition:
	$a0
}