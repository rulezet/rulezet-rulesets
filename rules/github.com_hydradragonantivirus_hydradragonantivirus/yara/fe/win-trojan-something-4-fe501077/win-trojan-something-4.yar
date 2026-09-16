rule Win_Trojan_Something_4
{
strings:
	$a0 = { d8b9ffff1e5233d22e8e1e8303b43fcd21725f3d00e873 }


condition:
	$a0
}