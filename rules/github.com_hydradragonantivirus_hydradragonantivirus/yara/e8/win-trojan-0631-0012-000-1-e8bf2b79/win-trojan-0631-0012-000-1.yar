rule Win_Trojan__0631_0012_000_1
{
strings:
	$a0 = { 023dba9e00cd2193b440ba0001b97f02cd21b43ecd21b44febdaba5802b409fec6cd21cd202a }


condition:
	$a0
}