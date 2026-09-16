rule Win_Trojan_Trivial_134
{
strings:
	$a0 = { b44e41ba1901cd21ba9e00b8023dcd2193b440ba0001cd21c3 }


condition:
	$a0
}