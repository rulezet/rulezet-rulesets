rule Win_Trojan_Saratoga_2
{
strings:
	$a0 = { cb26c6067f03ffb452cd21268b47fe8e }


condition:
	$a0
}