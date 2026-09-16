rule Win_Trojan_Mandra_2
{
strings:
	$a0 = { 3fb91d0233d2fec4cd21b8004233c933d2cd21b43fb903 }


condition:
	$a0
}