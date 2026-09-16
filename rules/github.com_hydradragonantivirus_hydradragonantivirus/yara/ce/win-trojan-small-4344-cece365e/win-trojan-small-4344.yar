rule Win_Trojan_Small_4344
{
strings:
	$a0 = { e85d000000e90900000086c95ec3e976000000 }


condition:
	$a0
}