rule Win_Spyware_3461_1
{
strings:
	$a0 = { 56687f2ff30b5e3134245e56be0600a00481ee87d0acf8313424 }


condition:
	$a0
}