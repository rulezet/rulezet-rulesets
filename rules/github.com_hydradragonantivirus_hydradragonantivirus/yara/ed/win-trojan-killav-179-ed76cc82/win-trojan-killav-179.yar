rule Win_Trojan_Killav_179
{
strings:
	$a0 = { 726570203d[0-30]5c6e6f72746f6e20616e74 }

	$a1 = { 66732e64656c657465666f6c646572202872657029 }

	$a2 = { 66616d696c79206564 }


condition:
	$a0 and $a1 and $a2
}