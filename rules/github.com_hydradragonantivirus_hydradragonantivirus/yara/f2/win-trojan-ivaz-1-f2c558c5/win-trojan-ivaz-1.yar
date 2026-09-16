rule Win_Trojan_Ivaz_1
{
strings:
	$a0 = { eb0060928db266030000b807000000e8150200005581ec4905 }

	$a1 = { 633a5c[0-13]5c416e7469566972616c2054 }


condition:
	$a0 and $a1
}