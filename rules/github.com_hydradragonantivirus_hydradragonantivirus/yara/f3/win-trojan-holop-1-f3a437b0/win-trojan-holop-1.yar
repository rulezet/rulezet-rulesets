rule Win_Trojan_Holop_1
{
strings:
	$a0 = { 4f5021042e45584501209a00007a005589e581ec0202bfaa1a1e57bfac1a1e57bfae1a1e57 }


condition:
	$a0
}