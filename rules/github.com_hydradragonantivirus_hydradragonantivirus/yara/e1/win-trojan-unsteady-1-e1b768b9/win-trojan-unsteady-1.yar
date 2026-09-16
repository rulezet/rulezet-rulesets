rule Win_Trojan_Unsteady_1
{
strings:
	$a0 = { c0a3a41a8dbe54ff1657bf80041e57b8231650bfac001e579a5408f7009a9102f700833ea41a00 }


condition:
	$a0
}