rule Win_Trojan_KEYDR_1
{
strings:
	$a0 = { c00733c08ed88ed0bc007c2e88161e00faa14c008b1e4e002ea324002e891e2600fba11304 }


condition:
	$a0
}